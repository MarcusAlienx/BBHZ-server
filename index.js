require('dotenv').config()
const express = require('express')
const cors = require('cors')
const cookieParser = require('cookie-parser')
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb')
const jwt = require('jsonwebtoken')
const morgan = require('morgan')
const stripe = require('stripe')(process.env.PAYMENT_KEY);
var admin = require("firebase-admin");
var serviceAccount = require("./config/houzezdeal-firebase-adminsdk-eye4c-f4a1bc0ff4.json");
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});





const port = process.env.PORT || 9000
const app = express()
// middleware
const corsOptions = {
  origin: ['http://localhost:5173', 'http://localhost:5175','https://houzezdeal.web.app','https://houzezdeal.firebaseapp.com'],
  credentials: true,
  optionSuccessStatus: 200,
}
app.use(cors(corsOptions))

app.use(express.json())
app.use(cookieParser())
app.use(morgan('dev'))



const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.n6sp6.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
})
async function run() {
  try {

    const db=client.db('houzez')
    const usersCollection=db.collection('users')
    const propertiesCollection=db.collection('properties')
    const wishlistCollection=db.collection('wishlists')
    const offersCollection=db.collection('offers')
    const reviwesCollection=db.collection('reviews')
   
    // Generate jwt token
    app.post('/jwt', async (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' });
      res.send({ token });
    })
      
    // verify token
    const verifyToken = (req, res, next) => {
      console.log('inside verify token', req.headers.authorization);
      if (!req.headers.authorization) {
        return res.status(401).send({ message: 'unauthorized access' });
      }
      const token = req.headers.authorization.split(' ')[1];
      jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) {
          return res.status(401).send({ message: 'unauthorized access' })
        }
        req.user= decoded;
        next();
      })
    }

  
    // verify admin middleware
    const verifyAdmin = async (req, res, next) => {
      console.log('req.user', req.user);
      const email = req.user?.email
      const query = { email: email }
      const user = await usersCollection.findOne(query)
      if (!user || user?.role !== 'admin') {
        return res.status(403).send({ message: 'forbidden access! ' })
      }
      next()
    }
 
    // verify agent middleware
    const verifyAgent = async (req, res, next) => {
      const email = req.user?.email
      const query = { email: email }
      const user = await usersCollection.findOne(query)
      if (!user || user?.role !== 'agent') {
        return res.status(403).send({ message: 'forbidden access! ' })
      }
      next()
    }


    //get all users
    
    app.get('/users',verifyToken,verifyAdmin, async (req, res) => {
      const result = await usersCollection.find().toArray()
      res.send(result)
    })


  //  get all users role
   app.get('/user/role/:email', async (req, res) => {
  const email = req.params.email;
  const query = { email };
  const result = await usersCollection.findOne(query);
  res.send({role:result?.role});
    
  
});

    // save user data in db
    app.post('/users/:email', async (req, res) => {
      const email = req.params.email
      const user=req.body
      const query = { email }

      const isExist= await usersCollection.findOne(query)
      if (isExist) {
        return res.status(400).send({ message: 'user already exist' })
      }
      const result = await usersCollection.insertOne(user)
      res.send(result)
      console.log(result);

    })
   
// Update user role
app.patch('/user/:id',verifyToken,verifyAdmin, async (req, res) => {
  const id = req.params.id;
  const role = req.body.role;
  const query = { _id: new ObjectId(id) };
  const updateDoc = {
    $set: {
      role: role,
    },
  };
  const result = await usersCollection.updateOne(query, updateDoc);
  res.send(result);
});


// update fraud

app.patch('/user/fraud/:id', verifyToken, verifyAdmin, async (req, res) => {
  const id = req.params.id;
  const fraud = req.body.isFraud;  // true or false indicating if the user should be marked as fraud

  try {
      // Step 1: Update the user's fraud status
      const query = { _id: new ObjectId(id) };
      const updateDoc = {
          $set: {
              isFraud: fraud,
          },
      };

      // Update the user's fraud status
      const result = await usersCollection.updateOne(query, updateDoc);

      if (result.matchedCount === 0) {
          return res.status(404).send({ message: 'User not found' });
      }

      // Step 2: Update all properties added by this user (using agentEmail) to unverified
      const user = await usersCollection.findOne(query);  // Get the user details

      if (!user) {
          return res.status(404).send({ message: 'User not found' });
      }

      const agentEmail = user.email;  // Assuming the user's email is the identifier

      const propertiesUpdateResult = await propertiesCollection.updateMany(
          { agentEmail: agentEmail },  // Find properties by agentEmail
          { $set: { verified: false, verificationStatus: "unverified" } }  // Update the verified field
      );

      console.log(`${propertiesUpdateResult.modifiedCount} properties updated to unverified.`);

      // Send a success response
      res.send({ message: 'User marked as fraud, properties updated to unverified.' });

  } catch (error) {
      console.error("An error occurred:", error);
      res.status(500).send({ message: 'An error occurred while updating the user and properties.' });
  }
});




// delete user from db and firebase
app.delete("/users/delete/:id",verifyToken,verifyAdmin,async (req, res) => {
    try {
      const userId = req.params.id;
      if (!ObjectId.isValid(userId)) {
        return res.status(400).json({ message: "Invalid user ID" });
      }

      const user = await usersCollection.findOne({
        _id: new ObjectId(userId),
      });

      if (!user) {
        return res.status(404).json({ message: "User not found in MongoDB" });
      }

      // Delete user from MongoDB
      const result = await usersCollection.deleteOne({
        _id: new ObjectId(userId),
      });

      if (result.deletedCount > 0) {
        // Attempt to delete the user from Firebase
        try {
          const firebaseUser = await admin.auth().getUserByEmail(user.email);
          await admin.auth().deleteUser(firebaseUser.uid);
          console.log(`Deleted user: ${user.email} from Firebase`);

          res.status(200).json({
            message: "User deleted from MongoDB and Firebase",
          });
        } catch (firebaseError) {
          console.error(
            "Error deleting user from Firebase:",
            firebaseError.message
          );
          return res.status(500).json({
            message: "User deleted from MongoDB, but not from Firebase",
            error: firebaseError.message,
          });
        }
      } else {
        return res.status(404).json({ message: "User not found in MongoDB" });
      }
    } catch (error) {
      console.error("Server error:", error);
      res.status(500).json({ message: "Server error" });
    }
  }
);

 

    // save property data in db
    app.post('/properties', verifyToken, verifyAgent, async (req, res) => {
      const agentEmail = req.user?.email;  // Assuming `req.user.email` contains the agent's email after verifying the token
      const property = req.body;
  
      try {
          // Step 1: Check if the agent is marked as fraud using their email
          const agent = await usersCollection.findOne({ email: agentEmail });
  
          if (!agent) {
              return res.status(404).send({ message: 'Agent not found' });
          }
  
          if (agent.isFraud) {
              return res.send({ message: 'Fraud agents cannot add properties' });
          }
  
          // Step 2: If the agent is not fraud, allow adding the property
          const result = await propertiesCollection.insertOne(property);
          res.status(201).send(result);  // Send a success response
      } catch (error) {
          console.error("An error occurred:", error);
          res.status(500).send({ message: 'An error occurred while adding the property' });
      }
  });
  

    // get all properties
    app.get('/properties', async (req, res) => {
        try {
          const verify = req.query.verify; 
          const search = req.query.search; 
          const sortByPrice = req.query.sortByPrice;
          const isAdvertised = req.query.isAdvertised;
          const query = {};
      
          
          if (verify) {
            query.verificationStatus = verify;
          }

          if (isAdvertised) {
            query.isAdvertised = isAdvertised === 'true'; 
          }
      
        
          if (search) {
            query.$or = [
              { title: { $regex: search, $options: 'i' } }, 
              { location: { $regex: search, $options: 'i' } }, 
            ];
          }
      
          
          const sort = {};
          if (sortByPrice === 'asc') {
            sort.priceMin = 1;
          } else if (sortByPrice === 'desc') {
            sort.priceMin = -1;
          }
      
          
          const result = await propertiesCollection.find(query||{}).sort(sort).toArray();
      
          res.send(result);
        } catch (error) {
          console.error('Error fetching properties:', error);
          res.status(500).send({ error: 'Failed to fetch properties' });
        }
      });
      
    // get single property
    app.get('/propertie/:id',verifyToken, async (req, res) => {
      const id = req.params.id
      const query = { _id: new ObjectId(id) }
      const result = await propertiesCollection.findOne(query)
      res.send(result)
    })

    // get properties by user use query
    app.get('/property/:email', verifyToken,verifyAgent, async (req, res) => {
      const email = req.params.email
      const query = {agentEmail:email}
      const result = await propertiesCollection.find(query).toArray()
      res.send(result)
      
    })

    // update property status
    app.patch('/properties/:id',verifyToken,verifyAdmin, async (req, res) => {
        try {
          const id = req.params.id;
          const { verificationStatus } = req.body; 
      
        
          if (!["verified", "rejected"].includes(verificationStatus)) {
            return res.status(400).send({ error: "Invalid verification status" });
          }
      
    
          const query = { _id: new ObjectId(id) };
          const updatedDoc = {
            $set: {
              verificationStatus: verificationStatus,
              verified: verificationStatus === "verified", 
            },
          };
      
    
          const result = await propertiesCollection.updateOne(query, updatedDoc);
      
          if (result.modifiedCount > 0) {
            res.send({ message: "Property status updated successfully" });
          } else {
            res.status(404).send({ error: "Property not found or no changes made" });
          }
        } catch (error) {
          console.error("Error updating property status:", error);
          res.status(500).send({ error: "Failed to update property status" });
        }
      });
    
      
    // update property advertisement status
    app.patch('/properties/:id/advertise', verifyToken,verifyAdmin, async (req, res) => {
      
        const id = req.params.id;
        const { isAdvertised } = req.body;
    
        const query = { _id: new ObjectId(id) };
        const updatedDoc = {
          $set: {
            isAdvertised: isAdvertised,
          },
        };
    
        const result = await propertiesCollection.updateOne(query, updatedDoc);
        res.send(result)
    
     
    });


    // update property
  app.patch('/property/:id', verifyToken,verifyAgent, async (req, res) => {
    const id = req.params.id
    const data = req.body
    const query = { _id: new ObjectId(id) }
    const options = { upsert: true }
    const updateDoc = {
      $set: data
    }
    const result = await propertiesCollection.updateOne(query, updateDoc, options)
    res.send(result)

  })


    app.delete('/properties/:id',verifyToken,verifyAgent, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await propertiesCollection.deleteOne(query);
      res.send(result);
    })


    //get all wishlist
    app.get('/wishlist', async (req, res) => {
       const result = await wishlistCollection.find().toArray()
        res.send(result)
    }) 
     
    // get single wishlist
   

    // get wishlist by user 
    app.get('/wishlist/:email',verifyToken, async (req, res) => {
      const email = req.params.email
      const query = {userEmail:email}
      const result = await wishlistCollection.find(query).toArray()
      res.send(result)
      
    })

    app.get('/wishlists/:id', async (req, res) => {
        const id = req.params.id
        const query = { _id: new ObjectId(id) }
        const result = await wishlistCollection.findOne(query)
        res.send(result)
      })
  

    // save wishlist data in db
    app.post('/wishlist', async (req, res) => {
      const wishlist = req.body
      const result = await wishlistCollection.insertOne(wishlist)
      res.send(result)
    })
  
    // delete wishlist
    app.delete('/wishlist/:id',verifyToken, async (req, res) => {
      const id = req.params.id
      const query = { _id: new ObjectId(id) }
      const result = await wishlistCollection.deleteOne(query)
      res.send(result)
    })

    // get all offers
    app.get('/offers',verifyToken,verifyAgent, async (req, res) => {
      const email = req.query.email
      const status = req.query.status

      if(status){
        const query = {status:status}
        const result = await offersCollection.find(query).toArray()
        return res.send(result)
      }
      if (email) {
        const query = {agentEmail:email}
        const result = await offersCollection.find(query).toArray()
        return res.send(result)
      }
     


      const result = await offersCollection.find().toArray()
      res.send(result)
    })

    // get single offer
    app.get('/offers/:email', async (req, res) => {
      const email = req.params.email
      const query = {buyerEmail:email}
      const result = await offersCollection.find(query).toArray()
      res.send(result)
    })

    // save offer data in db
    app.post('/offers',verifyToken, async (req, res) => {
      
      const offer = req.body
      const result = await offersCollection.insertOne(offer)
      res.send(result)
    })
  
  // update offer status

    app.patch('/offers/:id/accept', verifyToken,verifyAgent, async (req, res) => {
      try {
        const offerId = req.params.id; 
        const { propertyId } = req.body; 
    
       
        const acceptQuery = { _id: new ObjectId(offerId) };
        const acceptUpdate = {
          $set: {
            status: 'accepted',
          },
        };
        await offersCollection.updateOne(acceptQuery, acceptUpdate);
    
       
        const rejectQuery = {
          propertyId: propertyId, 
          _id: { $ne: new ObjectId(offerId) }, 
        };
        const rejectUpdate = {
          $set: {
            status: 'rejected',
          },
        };
        const rejectResult = await offersCollection.updateMany(rejectQuery, rejectUpdate);
    
        res.send({
          message: 'Offer accepted, and other offers rejected successfully.',
          rejectedCount: rejectResult.modifiedCount,
        });
      } catch (error) {
        console.error('Error:', error);
        res.status(500).send({ error: 'Failed to update offers.' });
      }
    });
  

// upadte buying status
    app.patch('/offers/:id/bought',verifyToken, async (req, res) => {
      const id = req.params.id
      const transactionId = req.body
      const query = { _id: new ObjectId(id) }
      const result = await offersCollection.updateOne(query, {
        $set: {
          status: 'bought',
          transactionId: transactionId
        }
      })
      res.send(result)
      
    })

    // reject offer

  app.patch('/offers/:id/reject',verifyToken,verifyAgent, async (req, res) => {
    try {
      const offerId = req.params.id; 
      const { propertyId } = req.body; 
      const rejectQuery = { _id: new ObjectId(offerId) };
      const rejectUpdate = {
        $set: {
          status: 'rejected',
        },
      };
      const rejectResult = await offersCollection.updateOne(rejectQuery, rejectUpdate);
      res.send({
        message: 'Offer rejected successfully.',
        rejectedCount: rejectResult.modifiedCount,
      });
    } catch (error) {
      console.error('Error:', error);
      res.status(500).send({ error: 'Failed to update offers.' });
    }
  });
    


    // get all reviews
    app.get('/reviews', async (req, res) => {
      const result = await reviwesCollection.find().toArray()
      res.send(result)
    })
   
  //  get review for a property

  app.get('/review/:id', async (req, res) => {
    const id = req.params.id
    const query = { propertyId: id }
    const result = await reviwesCollection.find(query).toArray()
    res.send(result)
  })


    // get review for specific user
    app.get('/allreviews/:email',verifyToken, async (req, res) => {
      const email = req.params.email
      const query = { userEmail: email }
      const result = await reviwesCollection.find(query).toArray()
      res.send(result)
    })

    // save review data in db
    app.post('/reviews',verifyToken, async (req, res) => {
      const review = req.body
      review.date = new Date()
      const result = await reviwesCollection.insertOne(review)
      res.send(result)
    })
  
    // delete a review
    app.delete('/reviews/:id',verifyToken, async (req, res) => {
      const id = req.params.id
      const query = { _id: new ObjectId(id) }
      const result = await reviwesCollection.deleteOne(query)
      res.send(result)
    })


// payment intent
app.post('/create-payment-intent', async (req, res) => {
  const { offerAmount} = req.body;
  const amount = parseInt(offerAmount * 100);
  console.log(amount, 'amount inside the intent')

  const paymentIntent = await stripe.paymentIntents.create({
    amount: amount,
    currency: 'usd',
    payment_method_types: ['card']
  });

  res.send({
    clientSecret: paymentIntent.client_secret
  })
});



    // Send a ping to confirm a successful connection
    // await client.db('admin').command({ ping: 1 })
    // console.log(
    //   'Pinged your deployment. You successfully connected to MongoDB!'
    // )
  } finally {
    // Ensures that the client will close when you finish/error
  }
}
run().catch(console.dir)

app.get('/', (req, res) => {
  res.send('Hello from houzez Server..')
})

app.listen(port, () => {
  console.log(`houzez is running on port ${port}`)
})
