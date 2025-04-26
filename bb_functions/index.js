const functions = require("firebase-functions/v2/https");
const admin = require("firebase-admin");
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const morgan = require("morgan");
// Assuming STRIPE_SECRET_KEY is set via Firebase Secret Manager or similar
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

// Initialize Firebase Admin SDK (auto-initialized in Cloud Functions env)
admin.initializeApp();

const app = express();

// Middleware
const corsOptions = {
  // Adjust origins as needed for your frontend URL(s)
  origin: [
    "http://localhost:5173",
    "http://localhost:5175",
    //"https://houzezdeal.web.app", // Example deployed frontend
    // Your Firebase project's hosting URL
    "https://buscabodega-1696627429011.web.app",
    // Alternative Firebase hosting URL
    "https://buscabodega-1696627429011.firebaseapp.com",
  ],
  credentials: true,
  optionSuccessStatus: 200,
};
app.use(cors(corsOptions));

app.use(express.json());
app.use(cookieParser());
// Use 'tiny' or remove morgan in production for less verbose logging
app.use(morgan("dev"));

// --- Firestore Initialization ---
const db = admin.firestore();
const usersCollection = db.collection("users");
const propertiesCollection = db.collection("properties");
const offersCollection = db.collection("offers");
const reviewsCollection = db.collection("reviews"); // Consider subcollection?
// Note: Using top-level collections for now.
// Subcollections might be better for reviews (properties/{propId}/reviews)
// and wishlists (users/{userId}/wishlist). Offers could also be subcollections.
// --- End Firestore Initialization ---


// --- Firebase Authentication Middleware ---

// Middleware to verify Firebase ID token
const verifyFirebaseToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    // eslint-disable-next-line max-len
    console.error("No Firebase ID token passed as Bearer in Authorization header.");
    return res.status(401).send({message: "Unauthorized: No token provided."});
  }

  const idToken = authHeader.split("Bearer ")[1];
  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    req.user = decodedToken; // Add Firebase user object to request
    console.log("Firebase token verified for UID:", req.user.uid);
    next();
  } catch (error) {
    console.error("Error while verifying Firebase ID token:", error);
    res.status(401).send({message: "Unauthorized: Invalid token."});
  }
};

// Middleware to verify if the user has an 'admin' custom claim
const verifyAdmin = (req, res, next) => {
  if (req.user && req.user.admin === true) {
    console.log("Admin verified:", req.user.uid);
    next();
  } else {
    console.error("Forbidden: User is not an admin.", req.user?.uid);
    res.status(403).send({
      message: "Forbidden: Requires admin privileges.",
    });
  }
  // TODO: Ensure custom claims are set correctly for admin users.
};

// Middleware to verify if the user has an 'agent' custom claim and is not marked as fraud
const verifyAgent = async (req, res, next) => { // Made async to use await
  if (req.user && req.user.agent === true) {
    try {
      const userDoc = await usersCollection.doc(req.user.uid).get();
      if (userDoc.exists && userDoc.data().isFraud) {
        console.error("Forbidden: Agent is marked as fraud.", req.user?.uid);
        return res.status(403).send({
          message: "Forbidden: Agent account is restricted.",
        });
      }
      console.log("Agent verified:", req.user.uid);
      next();
    } catch (error) {
      console.error("Error checking agent fraud status:", error);
      res.status(500).send({
        message: "Internal server error during agent verification.",
      });
    }
  } else {
    console.error("Forbidden: User is not an agent.", req.user?.uid);
    res.status(403).send({
      message: "Forbidden: Requires agent privileges.",
    });
  }
  // TODO: Ensure custom claims are set correctly for agent users.
};

// --- End Firebase Authentication Middleware ---


// --- Routes (Keep structure, update implementation later) ---

app.get("/", (req, res) => {
  res.send("Hello from Buscabodegas Firebase Server!");
});

// get all users
app.get("/users", verifyFirebaseToken, verifyAdmin, async (req, res) => {
  try {
    const snapshot = await usersCollection.get();
    const users = snapshot.docs.map((doc) => ({id: doc.id, ...doc.data()}));
    res.status(200).send(users);
  } catch (error) {
    console.error("Error getting users:", error);
    res.status(500).send({message: "Failed to retrieve users."});
  }
});

//  get user role by email
app.get("/user/role/:email", async (req, res) => {
  // Note: Prefer checking custom claims on the ID token if possible.
  // This endpoint might be redundant if roles are included in claims.
  const email = req.params.email;
  try {
    const querySnapshot = await usersCollection.where("email", "==", email)
        .limit(1).get();
    if (querySnapshot.empty) {
      return res.status(404).send({message: "User not found."});
    }
    const userDoc = querySnapshot.docs[0];
    res.status(200).send({role: userDoc.data()?.role || null});
  } catch (error) {
    console.error("Error getting user role by email:", error);
    res.status(500).send({message: "Failed to retrieve user role."});
  }
});

// save user profile data in Firestore after client-side Auth registration
app.post("/users", verifyFirebaseToken, async (req, res) => {
  // Expects user data (name, email, initial role etc.) and UID in req.body
  // The UID in req.user comes from the verified token,
  // ensuring the user is creating their own profile
  const userUid = req.user.uid;
  const userData = req.body;

  // Basic validation
  if (!userData.email || !userData.name) {
    return res.status(400).send({
      message: "Missing required user data (email, name).",
    });
  }

  // Ensure email in body matches token if provided (optional, good practice)
  if (userData.email && userData.email !== req.user.email) {
    console.warn(
        `Attempt to create profile for ${userData.email} by user ` +
        `${req.user.email} (${userUid})`,
    );
    // Decide on policy: reject, or use token email? Using token email is safer.
    // return res.status(403).send({ message: "Email does not match authenticated user." });
  }

  try {
    // Use the Firebase Auth UID as the document ID
    const userRef = usersCollection.doc(userUid);
    const doc = await userRef.get();

    if (doc.exists) {
      // Optionally update if exists, or return error
      console.log(`User profile already exists for UID: ${userUid}`);
      // You might want to allow updates via PUT/PATCH instead
      return res.status(409).send({message: "User profile already exists."});
    } else {
      // Create the user document in Firestore
      const profileData = {
        uid: userUid, // Store UID in the document as well
        email: req.user.email, // Use email from verified token
        name: userData.name,
        role: userData.role || "user", // Default role if not provided
        isFraud: false, // Default fraud status
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        // Add any other relevant fields from userData
      };
      await userRef.set(profileData);
      console.log(`User profile created for UID: ${userUid}`);
      // Return the created profile (without sensitive data if necessary)
      res.status(201).send({id: userRef.id, ...profileData});
    }
  } catch (error) {
    console.error("Error creating user profile:", error);
    res.status(500).send({message: "Failed to create user profile."});
  }
});

// Update user role (Sets custom claims and updates Firestore doc)
// Added /role for clarity
app.patch("/user/:uid/role", verifyFirebaseToken, verifyAdmin, async (req, res) => {
  const targetUid = req.params.uid;
  const {role} = req.body; // Expecting role: 'admin', 'agent', or 'user'

  if (!role || !["admin", "agent", "user"].includes(role)) {
    return res.status(400).send({
      message: "Invalid role specified. Must be 'admin', 'agent', or 'user'.",
    });
  }

  try {
    // 1. Set Custom Claims on Firebase Auth User
    const claims = {};
    if (role === "admin") {
      claims.admin = true;
      claims.agent = false; // Admins are not agents by default, adjust if needed
    } else if (role === "agent") {
      claims.admin = false;
      claims.agent = true;
    } else { // role === 'user'
      claims.admin = false;
      claims.agent = false;
    }
    await admin.auth().setCustomUserClaims(targetUid, claims);
    console.log(`Custom claims set for UID ${targetUid}:`, claims);

    // 2. Update role field in Firestore User Document
    const userRef = usersCollection.doc(targetUid);
    await userRef.update({role: role});
    console.log(`Firestore role updated for UID ${targetUid} to: ${role}`);

    // Optional: Force token refresh on client-side after this
    // by returning a specific status or message

    res.status(200).send({
      message: `User ${targetUid} role updated to ${role} and claims set.`,
    });
  } catch (error) {
    console.error(`Error updating role for UID ${targetUid}:`, error);
    if (error.code === "auth/user-not-found") {
      res.status(404).send({
        message: `User with UID ${targetUid} not found in Firebase Auth.`,
      });
    } else {
      res.status(500).send({message: "Failed to update user role and claims."});
    }
  }
});

// update user fraud status and related properties
app.patch("/user/:uid/fraud", verifyFirebaseToken, verifyAdmin, async (req, res) => { // Changed path
  const targetUid = req.params.uid;
  const isFraud = req.body.isFraud; // Expecting boolean true or false

  if (typeof isFraud !== "boolean") {
    return res.status(400).send({
      message: "Invalid 'isFraud' value. Must be true or false.",
    });
  }

  const userRef = usersCollection.doc(targetUid);

  try {
    // Use a batch write to update user and potentially properties atomically
    const batch = db.batch();

    // 1. Update the user document
    batch.update(userRef, {isFraud: isFraud});
    console.log(`User ${targetUid} fraud status set to ${isFraud}.`);

    // 2. If marking as fraud, find and update agent's properties
    let propertiesUpdatedCount = 0;
    if (isFraud === true) {
      // Find properties associated with this agent UID
      const propertiesQuery = propertiesCollection
          .where("agentUid", "==", targetUid);
      const propertiesSnapshot = await propertiesQuery.get();

      propertiesSnapshot.forEach((doc) => {
        // Update each property to be unverified
        batch.update(doc.ref, {
          verified: false,
          verificationStatus: "unverified", // Or perhaps 'revoked'?
        });
        propertiesUpdatedCount++;
      });
      console.log(
          `Marked ${propertiesUpdatedCount} properties from agent ` +
          `${targetUid} as unverified.`,
      );
    }
    // Note: If unmarking as fraud (isFraud === false), we generally don't
    // automatically re-verify properties. Re-verification would likely be
    // a separate admin action.

    // Commit the batch write
    await batch.commit();

    res.status(200).send({
      message: `User ${targetUid} fraud status updated to ${isFraud}. ` +
               `${propertiesUpdatedCount} properties updated.`,
    });
  } catch (error) {
    console.error(`Error updating fraud status for UID ${targetUid}:`, error);
    if (error.code === "not-found") { // Check error code for Firestore not found
      res.status(404).send({message: `User with UID ${targetUid} not found.`});
    } else {
      res.status(500).send({message: "Failed to update fraud status."});
    }
  }
});

// delete user from Firebase Auth and Firestore
app.delete("/users/delete/:uid", verifyFirebaseToken, verifyAdmin, async (req, res) => {
  const targetUid = req.params.uid;

  // Prevent admin from deleting themselves? Optional check.
  // if (req.user.uid === targetUid) {
  //   return res.status(400).send({ message: "Admin cannot delete themselves." });
  // }

  try {
    // 1. Delete from Firebase Authentication
    await admin.auth().deleteUser(targetUid);
    console.log(`Successfully deleted user ${targetUid} from Firebase Auth.`);

    // 2. Delete from Firestore
    const userRef = usersCollection.doc(targetUid);
    await userRef.delete();
    console.log(`Successfully deleted user profile ${targetUid} from Firestore.`);

    // --- Delete associated data ---
    const batch = db.batch();
    let deletedCount = 0;

    // Delete properties owned by this agent
    const propertiesSnapshot = await propertiesCollection
        .where("agentUid", "==", targetUid).get();
    propertiesSnapshot.forEach((doc) => {
      batch.delete(doc.ref);
      deletedCount++;
    });
    console.log(`Marked ${propertiesSnapshot.size} properties for deletion.`);

    // Delete offers made by this buyer
    const buyerOffersSnapshot = await offersCollection
        .where("buyerUid", "==", targetUid).get();
    buyerOffersSnapshot.forEach((doc) => {
      batch.delete(doc.ref);
      deletedCount++;
    });
    console.log(`Marked ${buyerOffersSnapshot.size} buyer offers for deletion.`);

    // Delete offers received by this agent (for their properties)
    // Note: May overlap if offers are subcollections of properties.
    // Given top-level 'offers', delete where agentUid matches.
    const agentOffersSnapshot = await offersCollection
        .where("agentUid", "==", targetUid).get();
    agentOffersSnapshot.forEach((doc) => {
      // Avoid double-counting if offer is both by/for same user (unlikely)
      if (!buyerOffersSnapshot.docs.some((buyerDoc) => buyerDoc.id === doc.id)) {
        batch.delete(doc.ref);
        deletedCount++;
      }
    });
    console.log(
        `Marked ${agentOffersSnapshot.size} agent offers for deletion ` +
        `(excluding buyer offers).`,
    );


    // Delete reviews written by this user
    const reviewsSnapshot = await reviewsCollection
        .where("userUid", "==", targetUid).get();
    reviewsSnapshot.forEach((doc) => {
      batch.delete(doc.ref);
      deletedCount++;
    });
    console.log(`Marked ${reviewsSnapshot.size} reviews for deletion.`);

    // Commit the batch write
    await batch.commit();
    console.log(
        `Successfully deleted ${deletedCount} associated documents for user ${targetUid}.`,
    );
    // --- End Delete associated data ---


    res.status(200).send({
      message: `Successfully deleted user ${targetUid} and associated data.`,
    });
  } catch (error) {
    console.error(`Error deleting user ${targetUid}:`, error);
    if (error.code === "auth/user-not-found") {
      // If user not found in Auth, maybe still try deleting from Firestore?
      try {
        await usersCollection.doc(targetUid).delete();
        console.log(
            `User ${targetUid} not found in Auth, but deleted from Firestore.`,
        );
        // Still attempt to delete associated data even if Auth user wasn't found
        const batch = db.batch();
        let deletedCount = 0;

        const propertiesSnapshot = await propertiesCollection
            .where("agentUid", "==", targetUid).get();
        propertiesSnapshot.forEach((doc) => {
          batch.delete(doc.ref); deletedCount++;
        });

        const buyerOffersSnapshot = await offersCollection
            .where("buyerUid", "==", targetUid).get();
        buyerOffersSnapshot.forEach((doc) => {
          batch.delete(doc.ref); deletedCount++;
        });

        const agentOffersSnapshot = await offersCollection
            .where("agentUid", "==", targetUid).get();
        agentOffersSnapshot.forEach((doc) => {
          if (!buyerOffersSnapshot.docs.some((buyerDoc) => buyerDoc.id === doc.id)) {
            batch.delete(doc.ref);
            deletedCount++;
          }
        });

        const reviewsSnapshot = await reviewsCollection
            .where("userUid", "==", targetUid).get();
        reviewsSnapshot.forEach((doc) => {
          batch.delete(doc.ref); deletedCount++;
        });

        await batch.commit();
        console.log(
            `Successfully deleted ${deletedCount} associated documents ` +
             `for user ${targetUid} (Auth user not found).`,
        );

        return res.status(200).send({
          message: `User ${targetUid} deleted from Firestore and associated ` +
                    `data (was not in Auth).`,
        });
      } catch (firestoreError) {
        console.error(
            `Error deleting user ${targetUid} from Firestore and associated ` +
             `data after Auth error:`, firestoreError,
        );
        return res.status(500).send({
          message: "Failed to delete user/associated data (Auth/Firestore err).",
        });
      }
    }
    res.status(500).send({
      message: "Failed to delete user and associated data.",
    });
  }
});

// save property data in db
app.post("/properties", verifyFirebaseToken, verifyAgent, async (req, res) => {
  const agentUid = req.user.uid;
  const propertyData = req.body;

  // Basic validation (add more as needed)
  if (!propertyData.title ||
      !propertyData.location ||
      !propertyData.priceMin) {
    return res.status(400).send({
      message: "Missing required property data (title, location, priceMin).",
    });
  }

  try {
    // Check if agent is marked as fraud (re-check for safety)
    const agentDoc = await usersCollection.doc(agentUid).get();
    if (!agentDoc.exists || agentDoc.data().isFraud) {
      console.error(
          `Attempt add property by fraudulent/non-existent agent: ${agentUid}`,
      );
      return res.status(403).send({
        message: "Forbidden: Agent account is restricted or not found.",
      });
    }

    // Prepare property document
    const newProperty = {
      ...propertyData,
      agentUid: agentUid, // Add agent's UID
      agentName: agentDoc.data().name || req.user.name, // Add agent's name
      agentEmail: agentDoc.data().email || req.user.email, // Add agent's email
      verificationStatus: "pending", // Default status
      verified: false,
      isAdvertised: false, // Default advertisement status
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    };

    // Add the property to Firestore
    const docRef = await propertiesCollection.add(newProperty);
    console.log(`Property created with ID: ${docRef.id} by agent ${agentUid}`);

    res.status(201).send({id: docRef.id, ...newProperty});
  } catch (error) {
    console.error("Error saving property:", error);
    res.status(500).send({message: "Failed to save property."});
  }
});

// get all properties (publicly accessible, consider adding filtering/pagination later)
app.get("/properties", async (req, res) => {
  try {
    // For now, fetch all properties. Add filters for 'verified: true' later.
    const snapshot = await propertiesCollection.get();
    const properties = snapshot.docs.map((doc) => ({id: doc.id, ...doc.data()}));
    res.status(200).send(properties);
  } catch (error) {
    console.error("Error getting properties:", error);
    res.status(500).send({message: "Failed to retrieve properties."});
  }
});

// get single property by ID
app.get("/propertie/:id", verifyFirebaseToken, async (req, res) => {
  const propertyId = req.params.id; // Firestore document ID

  try {
    const propertyRef = propertiesCollection.doc(propertyId);
    const doc = await propertyRef.get();

    if (!doc.exists) {
      return res.status(404).send({message: "Property not found."});
    }

    const propertyData = doc.data();

    // Add verification check for public access:
    // Allow access if property is verified OR user is admin OR owning agent.
    const isVerified = propertyData.verified === true;
    const isAdmin = req.user && req.user.admin === true;
    const isOwner = req.user && req.user.uid === propertyData.agentUid;

    if (!isVerified && !isAdmin && !isOwner) {
      console.warn(
          `Forbidden: User ${req.user?.uid} access unverified prop ${propertyId}.`,
      );
      return res.status(403).send({
        message: "Forbidden: Property not verified or access denied.",
      });
    }

    res.status(200).send({id: doc.id, ...propertyData});
  } catch (error) {
    console.error(`Error getting property ${propertyId}:`, error);
    res.status(500).send({message: "Failed to retrieve property."});
  }
});

// get properties listed by the authenticated agent
app.get("/property/agent", verifyFirebaseToken, verifyAgent, async (req, res) => {
  const agentUid = req.user.uid; // Get UID from verified token

  try {
    const propertiesQuery = propertiesCollection
        .where("agentUid", "==", agentUid);
    const snapshot = await propertiesQuery.get();

    if (snapshot.empty) {
      console.log(`No properties found for agent: ${agentUid}`);
      return res.status(200).send([]); // Return empty array if no properties found
    }

    const properties = snapshot.docs.map((doc) => ({id: doc.id, ...doc.data()}));
    res.status(200).send(properties);
  } catch (error) {
    console.error(`Error getting properties for agent ${agentUid}:`, error);
    res.status(500).send({message: "Failed to retrieve agent properties."});
  }
});

// update property status (verification) by Admin
app.patch("/properties/:id/status", verifyFirebaseToken, verifyAdmin, async (req, res) => {
  const propertyId = req.params.id; // Firestore document ID
  const {verified, verificationStatus} = req.body; // Expecting boolean 'verified' and string 'verificationStatus'

  // Basic validation
  if (typeof verified !== "boolean" || !verificationStatus) {
    return res.status(400).send({
      message: "Invalid input. Requires 'verified' (boolean) and " +
               "'verificationStatus' (string).",
    });
  }
  // Optional: Validate verificationStatus against allowed values
  const allowedStatuses = ["verified", "rejected", "pending"];
  if (!allowedStatuses.includes(verificationStatus)) {
    return res.status(400).send({
      message: `Invalid verificationStatus. Must be one of: ` +
               `${allowedStatuses.join(", ")}.`,
    });
  }

  try {
    const propertyRef = propertiesCollection.doc(propertyId);
    const doc = await propertyRef.get();

    if (!doc.exists) {
      return res.status(404).send({message: "Property not found."});
    }

    // Update the property document
    await propertyRef.update({
      verified: verified,
      verificationStatus: verificationStatus,
      // Optionally add updatedAt timestamp
      // updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    console.log(
        `Property ${propertyId} status updated by admin ${req.user.uid}: ` +
        `verified=${verified}, status=${verificationStatus}`,
    );
    res.status(200).send({
      message: `Property ${propertyId} status updated successfully.`,
    });
  } catch (error) {
    console.error(`Error updating status for property ${propertyId}:`, error);
    res.status(500).send({message: "Failed to update property status."});
  }
});

// update property advertisement status by Admin
app.patch("/properties/:id/advertise", verifyFirebaseToken, verifyAdmin, async (req, res) => {
  const propertyId = req.params.id; // Firestore document ID
  const {isAdvertised} = req.body; // Expecting boolean 'isAdvertised'

  // Basic validation
  if (typeof isAdvertised !== "boolean") {
    return res.status(400).send({
      message: "Invalid input. Requires 'isAdvertised' (boolean).",
    });
  }

  try {
    const propertyRef = propertiesCollection.doc(propertyId);
    const doc = await propertyRef.get();

    if (!doc.exists) {
      return res.status(404).send({message: "Property not found."});
    }

    // Update the property document
    await propertyRef.update({
      isAdvertised: isAdvertised,
      // Optionally add updatedAt timestamp
      // updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    console.log(
        `Property ${propertyId} advertisement status updated by admin ` +
        `${req.user.uid}: isAdvertised=${isAdvertised}`,
    );
    res.status(200).send({
      message: `Property ${propertyId} advertisement status updated successfully.`,
    });
  } catch (error) {
    console.error(
        `Error updating advertisement status for property ${propertyId}:`, error,
    );
    res.status(500).send({
      message: "Failed to update property advertisement status.",
    });
  }
});

// update property details by the owning Agent
app.patch("/property/:id", verifyFirebaseToken, verifyAgent, async (req, res) => {
  const propertyId = req.params.id; // Firestore document ID
  const agentUid = req.user.uid; // UID of the authenticated agent
  const updatedData = req.body; // Data to update

  // Remove fields that agents shouldn't be able to modify directly
  delete updatedData.agentUid;
  delete updatedData.agentName; // Should be derived from user profile
  delete updatedData.agentEmail; // Should be derived from user profile
  delete updatedData.verified;
  delete updatedData.verificationStatus;
  delete updatedData.isAdvertised; // Should be updated via admin route
  delete updatedData.createdAt;
  delete updatedData.updatedAt; // We'll set this with server timestamp

  if (Object.keys(updatedData).length === 0) {
    return res.status(400).send({
      message: "No valid fields provided for update.",
    });
  }

  try {
    const propertyRef = propertiesCollection.doc(propertyId);
    const doc = await propertyRef.get();

    if (!doc.exists) {
      return res.status(404).send({message: "Property not found."});
    }

    const propertyData = doc.data();

    // Verify ownership
    if (propertyData.agentUid !== agentUid) {
      console.error(
          `Forbidden: Agent ${agentUid} attempted to update property ` +
          `${propertyId} owned by ${propertyData.agentUid}`,
      );
      return res.status(403).send({
        message: "Forbidden: You do not have permission to update this property.",
      });
    }

    // Update the property document
    await propertyRef.update({
      ...updatedData,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(), // Add update timestamp
    });

    console.log(`Property ${propertyId} updated by owner agent ${agentUid}`);
    // Fetch the updated document to return it
    const updatedDoc = await propertyRef.get();
    res.status(200).send({id: updatedDoc.id, ...updatedDoc.data()});
  } catch (error) {
    console.error(
        `Error updating property ${propertyId} by agent ${agentUid}:`, error,
    );
    res.status(500).send({message: "Failed to update property details."});
  }
});

// delete property by the owning Agent
app.delete("/properties/:id", verifyFirebaseToken, verifyAgent, async (req, res) => {
  const propertyId = req.params.id; // Firestore document ID
  const agentUid = req.user.uid; // UID of the authenticated agent

  try {
    const propertyRef = propertiesCollection.doc(propertyId);
    const doc = await propertyRef.get();

    if (!doc.exists) {
      return res.status(404).send({message: "Property not found."});
    }

    const propertyData = doc.data();

    // Verify ownership
    if (propertyData.agentUid !== agentUid) {
      console.error(
          `Forbidden: Agent ${agentUid} attempted to delete property ` +
          `${propertyId} owned by ${propertyData.agentUid}`,
      );
      return res.status(403).send({
        message: "Forbidden: You do not have permission to delete this property.",
      });
    }

    // Delete the property document
    await propertyRef.delete();

    console.log(`Property ${propertyId} deleted by owner agent ${agentUid}`);
    res.status(200).send({
      message: `Property ${propertyId} deleted successfully.`,
    });
  } catch (error) {
    console.error(
        `Error deleting property ${propertyId} by agent ${agentUid}:`, error,
    );
    res.status(500).send({message: "Failed to delete property."});
  }
});

// --- Wishlist Routes ---

// Get wishlist for the authenticated user
app.get("/wishlist/user", verifyFirebaseToken, async (req, res) => {
  const userUid = req.user.uid; // Get UID from verified token

  try {
    // Assuming wishlists are stored in a subcollection under the user document
    const userWishlistCollection = usersCollection.doc(userUid)
        .collection("wishlist");
    const snapshot = await userWishlistCollection.get();

    if (snapshot.empty) {
      console.log(`No wishlist found for user: ${userUid}`);
      return res.status(200).send([]); // Return empty array if no wishlist found
    }

    const wishlistItems = snapshot.docs.map((doc) => ({
      id: doc.id, ...doc.data(),
    }));
    res.status(200).send(wishlistItems);
  } catch (error) {
    console.error(`Error getting wishlist for user ${userUid}:`, error);
    res.status(500).send({message: "Failed to retrieve user wishlist."});
  }
});

// Add a property to the authenticated user's wishlist
app.post("/wishlist", verifyFirebaseToken, async (req, res) => {
  const userUid = req.user.uid; // Get UID from verified token
  const {propertyId} = req.body; // Expecting propertyId in the request body

  // Basic validation
  if (!propertyId) {
    return res.status(400).send({message: "Missing required propertyId."});
  }

  try {
    // Check if the property exists (optional but good practice)
    const propertyDoc = await propertiesCollection.doc(propertyId).get();
    if (!propertyDoc.exists) {
      return res.status(404).send({message: "Property not found."});
    }

    // Assuming wishlists are stored in a subcollection under the user document
    const userWishlistCollection = usersCollection.doc(userUid)
        .collection("wishlist");

    // Check if the property is already in the wishlist (optional)
    const existingItemQuery = userWishlistCollection
        .where("propertyId", "==", propertyId).limit(1);
    const existingItem = await existingItemQuery.get();
    if (!existingItem.empty) {
      console.log(
          `Property ${propertyId} already in wishlist for user ${userUid}`,
      );
      return res.status(409).send({message: "Property already in wishlist."});
    }

    // Add the property to the wishlist subcollection
    const newWishlistItem = {
      propertyId: propertyId,
      addedAt: admin.firestore.FieldValue.serverTimestamp(),
      // Optionally add other relevant property details here if needed
      // for display without fetching property again
    };

    const docRef = await userWishlistCollection.add(newWishlistItem);
    console.log(
        `Property ${propertyId} added to wishlist for user ${userUid} ` +
        `with ID: ${docRef.id}`,
    );

    res.status(201).send({id: docRef.id, ...newWishlistItem});
  } catch (error) {
    console.error(
        `Error adding property ${propertyId} to wishlist for user ${userUid}:`,
        error,
    );
    res.status(500).send({message: "Failed to add property to wishlist."});
  }
});

// Remove a property from the authenticated user's wishlist
app.delete("/wishlist/:id", verifyFirebaseToken, async (req, res) => {
  const wishlistItemId = req.params.id; // Firestore document ID of the wishlist item
  const userUid = req.user.uid; // Get UID from verified token

  try {
    // Assuming wishlists are stored in a subcollection under the user document
    const wishlistItemRef = usersCollection.doc(userUid)
        .collection("wishlist").doc(wishlistItemId);
    const doc = await wishlistItemRef.get();

    if (!doc.exists) {
      return res.status(404).send({message: "Wishlist item not found."});
    }

    // Note: Ownership is implicitly checked by accessing the subcollection
    // under userUid. If the wishlist item document ID was globally unique
    // and not under the user's UID, we would need to verify
    // doc.data().userUid === userUid explicitly. Based on the GET
    // /wishlist/user implementation, the current structure implies the
    // wishlist item document is directly under the user's UID subcollection.

    // Delete the wishlist item document
    await wishlistItemRef.delete();

    console.log(`Wishlist item ${wishlistItemId} deleted for user ${userUid}`);
    res.status(200).send({
      message: `Wishlist item ${wishlistItemId} deleted successfully.`,
    });
  } catch (error) {
    console.error(
        `Error deleting wishlist item ${wishlistItemId} for user ${userUid}:`,
        error,
    );
    res.status(500).send({message: "Failed to delete wishlist item."});
  }
});

// --- Offers Routes ---
// Get offers for properties managed by the authenticated agent
app.get("/offers/agent", verifyFirebaseToken, verifyAgent, async (req, res) => {
  const agentUid = req.user.uid; // Get UID from verified token

  try {
    // Find properties owned by this agent
    const propertiesSnapshot = await propertiesCollection
        .where("agentUid", "==", agentUid).get();
    if (propertiesSnapshot.empty) {
      console.log(`No properties found for agent ${agentUid}, thus no offers.`);
      // No properties means no offers for this agent
      return res.status(200).send([]);
    }

    // Get the IDs of properties owned by the agent
    const propertyIds = propertiesSnapshot.docs.map((doc) => doc.id);

    // Find offers related to these property IDs
    // Note: Firestore 'in' query limit is 10 elements.
    // If agent has >10 props, this needs pagination/different approach.
    if (propertyIds.length === 0) {
      return res.status(200).send([]);
    }

    const offersSnapshot = await offersCollection
        .where("propertyId", "in", propertyIds).get();

    if (offersSnapshot.empty) {
      console.log(`No offers found for agent ${agentUid}'s properties.`);
      return res.status(200).send([]); // Return empty array if no offers found
    }

    const offers = offersSnapshot.docs.map((doc) => ({
      id: doc.id, ...doc.data(),
    }));
    res.status(200).send(offers);
  } catch (error) {
    console.error(`Error getting offers for agent ${agentUid}:`, error);
    res.status(500).send({message: "Failed to retrieve agent offers."});
  }
});

// Get offers made by the authenticated user (buyer)
app.get("/offers/buyer", verifyFirebaseToken, async (req, res) => {
  const buyerUid = req.user.uid; // Get UID from verified token

  try {
    const offersQuery = offersCollection.where("buyerUid", "==", buyerUid);
    const snapshot = await offersQuery.get();

    if (snapshot.empty) {
      console.log(`No offers found for buyer: ${buyerUid}`);
      return res.status(200).send([]); // Return empty array if no offers found
    }

    const offers = snapshot.docs.map((doc) => ({id: doc.id, ...doc.data()}));
    res.status(200).send(offers);
  } catch (error) {
    console.error(`Error getting offers for buyer ${buyerUid}:`, error);
    res.status(500).send({message: "Failed to retrieve buyer offers."});
  }
});

// Create a new offer for a property
app.post("/offers", verifyFirebaseToken, async (req, res) => {
  const buyerUid = req.user.uid; // Get UID from verified token
  // Expecting propertyId, offerAmount, and other details
  const {propertyId, offerAmount, ...otherOfferDetails} = req.body;

  // Basic validation
  if (!propertyId || !offerAmount ||
      typeof offerAmount !== "number" || offerAmount <= 0) {
    return res.status(400).send({
      message: "Invalid input. Requires valid 'propertyId' and positive 'offerAmount'.",
    });
  }

  try {
    // Check if the property exists and is verified
    const propertyDoc = await propertiesCollection.doc(propertyId).get();
    if (!propertyDoc.exists || !propertyDoc.data().verified) {
      return res.status(404).send({
        message: "Property not found or not verified.",
      });
    }

    const propertyData = propertyDoc.data();

    // Agents cannot make offers on their own properties
    if (propertyData.agentUid === buyerUid) {
      return res.status(403).send({
        message: "Forbidden: You cannot make an offer on your own property.",
      });
    }

    // Prepare offer document
    const newOffer = {
      propertyId: propertyId,
      buyerUid: buyerUid,
      agentUid: propertyData.agentUid, // Store agent's UID for easy query
      offerAmount: offerAmount,
      status: "pending", // Initial status
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      ...otherOfferDetails, // Include other details from body
    };

    // Add the offer to Firestore
    const docRef = await offersCollection.add(newOffer);
    console.log(
        `Offer created with ID: ${docRef.id} for property ${propertyId} ` +
        `by buyer ${buyerUid}`,
    );

    res.status(201).send({id: docRef.id, ...newOffer});
  } catch (error) {
    console.error(
        `Error creating offer for property ${propertyId} by buyer ${buyerUid}:`,
        error,
    );
    res.status(500).send({message: "Failed to create offer."});
  }
});

// Accept an offer by the owning Agent
app.patch("/offers/:id/accept", verifyFirebaseToken, verifyAgent, async (req, res) => {
  const offerId = req.params.id; // Firestore document ID of the offer
  const agentUid = req.user.uid; // UID of the authenticated agent

  try {
    const offerRef = offersCollection.doc(offerId);
    const offerDoc = await offerRef.get();

    if (!offerDoc.exists) {
      return res.status(404).send({message: "Offer not found."});
    }

    const offerData = offerDoc.data();

    // Verify agent owns the property associated with this offer
    const propertyDoc = await propertiesCollection.doc(offerData.propertyId).get();
    if (!propertyDoc.exists || propertyDoc.data().agentUid !== agentUid) {
      console.error(
          `Forbidden: Agent ${agentUid} accept offer ${offerId} for prop ` +
          `${offerData.propertyId} not owned by them.`,
      );
      return res.status(403).send({
        message: "Forbidden: You do not have permission to accept this offer.",
      });
    }

    // Use a batch write for atomic updates
    const batch = db.batch();

    // 1. Update the accepted offer's status
    batch.update(offerRef, {
      status: "accepted",
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    console.log(`Offer ${offerId} status set to 'accepted' by agent ${agentUid}.`);

    // 2. (Optional) Find and reject other pending offers for same property
    const otherOffersQuery = offersCollection
        .where("propertyId", "==", offerData.propertyId)
        .where("status", "==", "pending")
        // Exclude the accepted offer
        .where(admin.firestore.FieldPath.documentId(), "!=", offerId);

    const otherOffersSnapshot = await otherOffersQuery.get();
    let rejectedCount = 0;
    otherOffersSnapshot.forEach((doc) => {
      batch.update(doc.ref, {
        status: "rejected",
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });
      rejectedCount++;
    });
    if (rejectedCount > 0) {
      console.log(
          `Rejected ${rejectedCount} other pending offers for property ${offerData.propertyId}.`,
      );
    }


    // 3. (Optional) Update the property status to 'sold' or similar
    // const propertyRef = propertiesCollection.doc(offerData.propertyId);
    // batch.update(propertyRef, {
    //   status: 'sold', // Or another appropriate status
    //   updatedAt: admin.firestore.FieldValue.serverTimestamp()
    // });
    // console.log(`Property ${offerData.propertyId} status updated to 'sold'.`);


    // Commit the batch write
    await batch.commit();

    res.status(200).send({
      message: `Offer ${offerId} accepted. ${rejectedCount} other offers rejected.`,
    });
  } catch (error) {
    console.error(`Error accepting offer ${offerId} by agent ${agentUid}:`, error);
    res.status(500).send({message: "Failed to accept offer."});
  }
});

// Mark an offer as bought by the buyer (after payment confirmation)
app.patch("/offers/:id/bought", verifyFirebaseToken, async (req, res) => {
  const offerId = req.params.id; // Firestore document ID of the offer
  const userUid = req.user.uid; // UID of the authenticated user

  try {
    const offerRef = offersCollection.doc(offerId);
    const offerDoc = await offerRef.get();

    if (!offerDoc.exists) {
      return res.status(404).send({message: "Offer not found."});
    }

    const offerData = offerDoc.data();

    // Verify authenticated user is the buyer of this offer
    if (offerData.buyerUid !== userUid) {
      console.error(
          `Forbidden: User ${userUid} tried marking offer ${offerId} ` +
          `as bought, but is not the buyer.`,
      );
      return res.status(403).send({
        message: "Forbidden: You do not have permission to update this offer.",
      });
    }

    // Optional: Check current offer status (e.g., must be 'accepted')
    if (offerData.status !== "accepted") {
      return res.status(400).send({
        message: `Offer must be 'accepted' before being marked as bought. ` +
                 `Current status: ${offerData.status}`,
      });
    }


    // Update the offer's status to 'bought'
    await offerRef.update({
      status: "bought", // Or 'completed', 'paid', etc.
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      // Optionally add payment confirmation details here
    });

    console.log(`Offer ${offerId} marked as bought by buyer ${userUid}`);
    res.status(200).send({
      message: `Offer ${offerId} marked as bought successfully.`,
    });
  } catch (error) {
    console.error(
        `Error marking offer ${offerId} as bought by buyer ${userUid}:`, error,
    );
    res.status(500).send({message: "Failed to mark offer as bought."});
  }
});

// Reject an offer by the owning Agent
app.patch("/offers/:id/reject", verifyFirebaseToken, verifyAgent, async (req, res) => {
  const offerId = req.params.id; // Firestore document ID of the offer
  const agentUid = req.user.uid; // UID of the authenticated agent

  try {
    const offerRef = offersCollection.doc(offerId);
    const offerDoc = await offerRef.get();

    if (!offerDoc.exists) {
      return res.status(404).send({message: "Offer not found."});
    }

    const offerData = offerDoc.data();

    // Verify agent owns the property associated with this offer
    const propertyDoc = await propertiesCollection.doc(offerData.propertyId).get();
    if (!propertyDoc.exists || propertyDoc.data().agentUid !== agentUid) {
      console.error(
          `Forbidden: Agent ${agentUid} reject offer ${offerId} for prop ` +
          `${offerData.propertyId} not owned by them.`,
      );
      return res.status(403).send({
        message: "Forbidden: You do not have permission to reject this offer.",
      });
    }

    // Optional: Check current offer status (e.g., must be 'pending'/'accepted')
    if (offerData.status !== "pending" && offerData.status !== "accepted") {
      return res.status(400).send({
        message: `Offer must be 'pending' or 'accepted' to be rejected. ` +
                 `Current status: ${offerData.status}`,
      });
    }

    // Update the offer's status to 'rejected'
    await offerRef.update({
      status: "rejected",
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    console.log(`Offer ${offerId} status set to 'rejected' by agent ${agentUid}.`);
    res.status(200).send({message: `Offer ${offerId} rejected successfully.`});
  } catch (error) {
    console.error(`Error rejecting offer ${offerId} by agent ${agentUid}:`, error);
    res.status(500).send({message: "Failed to reject offer."});
  }
});

// Get reviews for a specific property
app.get("/reviews", async (req, res) => {
  const propertyId = req.query.propertyId; // Expecting propertyId as query param

  // Basic validation
  if (!propertyId) {
    return res.status(400).send({
      message: "Missing required propertyId query parameter.",
    });
  }

  try {
    // Optional: Check if property exists (good practice)
    const propertyDoc = await propertiesCollection.doc(propertyId).get();
    if (!propertyDoc.exists) {
      return res.status(404).send({message: "Property not found."});
    }

    const reviewsQuery = reviewsCollection
        .where("propertyId", "==", propertyId)
        .orderBy("createdAt", "desc"); // Order by newest first
    const snapshot = await reviewsQuery.get();

    if (snapshot.empty) {
      console.log(`No reviews found for property: ${propertyId}`);
      return res.status(200).send([]); // Return empty array if no reviews found
    }

    const reviews = snapshot.docs.map((doc) => ({id: doc.id, ...doc.data()}));
    res.status(200).send(reviews);
  } catch (error) {
    console.error(`Error getting reviews for property ${propertyId}:`, error);
    res.status(500).send({message: "Failed to retrieve reviews."});
  }
});

// Get reviews for a specific property by ID from path
app.get("/review/:id", async (req, res) => {
  const propertyId = req.params.id; // Get propertyId from path parameter

  try {
    // Optional: Check if property exists (good practice)
    const propertyDoc = await propertiesCollection.doc(propertyId).get();
    if (!propertyDoc.exists) {
      return res.status(404).send({message: "Property not found."});
    }

    const reviewsQuery = reviewsCollection
        .where("propertyId", "==", propertyId)
        .orderBy("createdAt", "desc"); // Order by newest first
    const snapshot = await reviewsQuery.get();

    if (snapshot.empty) {
      console.log(`No reviews found for property: ${propertyId}`);
      return res.status(200).send([]); // Return empty array if no reviews found
    }

    const reviews = snapshot.docs.map((doc) => ({id: doc.id, ...doc.data()}));
    res.status(200).send(reviews);
  } catch (error) {
    console.error(`Error getting reviews for property ${propertyId}:`, error);
    res.status(500).send({message: "Failed to retrieve reviews."});
  }
});

// Get reviews written by the authenticated user
app.get("/reviews/user", verifyFirebaseToken, async (req, res) => {
  const userUid = req.user.uid; // Get UID from verified token

  try {
    const reviewsQuery = reviewsCollection
        .where("userUid", "==", userUid)
        .orderBy("createdAt", "desc"); // Order by newest first
    const snapshot = await reviewsQuery.get();

    if (snapshot.empty) {
      console.log(`No reviews found for user: ${userUid}`);
      return res.status(200).send([]); // Return empty array if no reviews found
    }

    const reviews = snapshot.docs.map((doc) => ({id: doc.id, ...doc.data()}));
    res.status(200).send(reviews);
  } catch (error) {
    console.error(`Error getting reviews for user ${userUid}:`, error);
    res.status(500).send({message: "Failed to retrieve user reviews."});
  }
});

// Submit a review for a property
app.post("/reviews", verifyFirebaseToken, async (req, res) => {
  const userUid = req.user.uid; // Get UID from verified token
  // Expecting propertyId, rating, comment, and other details
  const {propertyId, rating, comment, ...otherReviewDetails} = req.body;

  // Basic validation
  if (!propertyId || typeof rating !== "number" ||
      rating < 1 || rating > 5 || !comment) {
    return res.status(400).send({
      message: "Invalid input. Requires valid 'propertyId', 'rating' (1-5), " +
               "and 'comment'.",
    });
  }

  try {
    // Optional: Check if user has a 'bought' offer for this property
    const boughtOfferQuery = offersCollection
        .where("buyerUid", "==", userUid)
        .where("propertyId", "==", propertyId)
        .where("status", "==", "bought")
        .limit(1);
    const boughtOfferSnapshot = await boughtOfferQuery.get();

    if (boughtOfferSnapshot.empty) {
      console.warn(
          `User ${userUid} review attempt on prop ${propertyId} ` +
          `without 'bought' offer.`,
      );
      // Decide on policy: allow reviews without purchase, or restrict?
      // For now, restricting reviews to buyers.
      return res.status(403).send({
        message: "Forbidden: You can only review properties you have bought.",
      });
    }

    // Check if the user has already reviewed this property (optional)
    const existingReviewQuery = reviewsCollection
        .where("userUid", "==", userUid)
        .where("propertyId", "==", propertyId)
        .limit(1);
    const existingReviewSnapshot = await existingReviewQuery.get();

    if (!existingReviewSnapshot.empty) {
      console.warn(`User ${userUid} already reviewed property ${propertyId}.`);
      return res.status(409).send({
        message: "You have already reviewed this property.",
      });
    }


    // Prepare review document
    const newReview = {
      propertyId: propertyId,
      userUid: userUid,
      userName: req.user.name || req.user.email, // Use name from token
      rating: rating,
      comment: comment,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      ...otherReviewDetails, // Include other details from body
    };

    // Add the review to Firestore
    const docRef = await reviewsCollection.add(newReview);
    console.log(
        `Review created with ID: ${docRef.id} for property ${propertyId} ` +
        `by user ${userUid}`,
    );

    // TODO: Consider updating property's average rating and review count here
    // or via a separate trigger function.

    res.status(201).send({id: docRef.id, ...newReview});
  } catch (error) {
    console.error(
        `Error creating review for property ${propertyId} by user ${userUid}:`,
        error,
    );
    res.status(500).send({message: "Failed to create review."});
  }
});

// Delete a review by the author or an Admin
app.delete("/reviews/:id", verifyFirebaseToken, async (req, res) => {
  const reviewId = req.params.id; // Firestore document ID of the review
  const userUid = req.user.uid; // UID of the authenticated user
  const isAdmin = req.user.admin === true; // Check if user is admin

  try {
    const reviewRef = reviewsCollection.doc(reviewId);
    const reviewDoc = await reviewRef.get();

    if (!reviewDoc.exists) {
      return res.status(404).send({message: "Review not found."});
    }

    const reviewData = reviewDoc.data();

    // Check if the user is the author of the review or an admin
    if (reviewData.userUid !== userUid && !isAdmin) {
      console.error(
          `Forbidden: User ${userUid} attempted to delete review ${reviewId} ` +
          `not owned by them and is not an admin.`,
      );
      return res.status(403).send({
        message: "Forbidden: You do not have permission to delete this review.",
      });
    }

    // Delete the review document
    await reviewRef.delete();

    console.log(`Review ${reviewId} deleted by user ${userUid} (Admin: ${isAdmin})`);

    // TODO: Consider updating property's average rating and review count here
    // or via a separate trigger function.

    res.status(200).send({
      message: `Review ${reviewId} deleted successfully.`,
    });
  } catch (error) {
    console.error(
        `Error deleting review ${reviewId} by user ${userUid}:`, error,
    );
    res.status(500).send({message: "Failed to delete review."});
  }
});

// --- Payment Route ---
// Create a Stripe payment intent
app.post("/create-payment-intent", verifyFirebaseToken, async (req, res) => {
  const {offerAmount, offerId} = req.body; // Expecting offerAmount and offerId

  // Basic validation
  if (!offerAmount || typeof offerAmount !== "number" ||
      offerAmount <= 0 || !offerId) {
    return res.status(400).send({
      message: "Invalid input. Requires valid 'offerAmount' and 'offerId'.",
    });
  }

  try {
    // Optional: Verify offer exists and is in 'accepted' status
    const offerRef = offersCollection.doc(offerId);
    const offerDoc = await offerRef.get();

    if (!offerDoc.exists) {
      return res.status(404).send({message: "Offer not found."});
    }

    const offerData = offerDoc.data();

    // Verify authenticated user is the buyer of this offer
    if (offerData.buyerUid !== req.user.uid) {
      console.error(
          `Forbidden: User ${req.user.uid} attempted to create payment ` +
          `intent for offer ${offerId} not made by them.`,
      );
      return res.status(403).send({
        message: "Forbidden: You do not have permission for this offer.",
      });
    }

    // Check if the offer is accepted
    if (offerData.status !== "accepted") {
      return res.status(400).send({
        message: `Payment intent can only be created for 'accepted' offers. ` +
                 `Current status: ${offerData.status}`,
      });
    }

    // Ensure STRIPE_SECRET_KEY is set as Firebase Function config or Secret Manager
    // Accessing secrets: https://firebase.google.com/docs/functions/config-env
    // For Secret Manager: const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
    // Ensure STRIPE_SECRET_KEY is set as Firebase Function config or Secret Manager
    // Accessing secrets: https://firebase.google.com/docs/functions/config-env
    // For Secret Manager: const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
    // For Runtime Config: const stripe = require('stripe')(functions.config().stripe.secret_key);

    // Create a PaymentIntent with the order amount and currency
    const paymentIntent = await stripe.paymentIntents.create({
      amount: parseInt(offerAmount * 100), // Amount in cents
      currency: "usd", // Or your desired currency
      metadata: {offerId: offerId, buyerUid: req.user.uid}, // Link payment
      // Add other parameters as needed, e.g., payment_method_types: ['card']
