require('dotenv').config()
const express = require('express')
const cors = require('cors')
const cookieParser = require('cookie-parser')
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb')
const jwt = require('jsonwebtoken')
const morgan = require('morgan')

const port = process.env.PORT || 9000
const app = express()
// middleware
const corsOptions = {
  origin: ['http://localhost:5173', 'http://localhost:5175'],
  credentials: true,
  optionSuccessStatus: 200,
}
app.use(cors(corsOptions))

app.use(express.json())
app.use(cookieParser())
app.use(morgan('dev'))

const verifyToken = async (req, res, next) => {
  const token = req.cookies?.token

  if (!token) {
    return res.status(401).send({ message: 'unauthorized access' })
  }
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      console.log(err)
      return res.status(401).send({ message: 'unauthorized access' })
    }
    req.user = decoded
    next()
  })
}

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
      const email = req.body
      const token = jwt.sign(email, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: '365d',
      })
      res
        .cookie('token', token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
        })
        .send({ success: true })
    })
    // Logout
    app.get('/logout', async (req, res) => {
      try {
        res
          .clearCookie('token', {
            maxAge: 0,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
          })
          .send({ success: true })
      } catch (err) {
        res.status(500).send(err)
      }
    })
  
  
    //get all users
    
    app.get('/users', async (req, res) => {
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
app.patch('/user/:id', async (req, res) => {
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


app.delete('/user/:id', async (req, res) => {
  const id = req.params.id;
  const query = { _id: new ObjectId(id) };
  const result = await usersCollection.deleteOne(query);
  res.send(result);
})
 

    // save property data in db
    app.post('/properties', async (req, res) => {
      const property = req.body
      const result = await propertiesCollection.insertOne(property)
      res.send(result)
    })

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
      
          
          const result = await propertiesCollection.find(query).sort(sort).toArray();
      
          res.send(result);
        } catch (error) {
          console.error('Error fetching properties:', error);
          res.status(500).send({ error: 'Failed to fetch properties' });
        }
      });
      
    // get single property
    app.get('/propertie/:id', async (req, res) => {
      const id = req.params.id
      const query = { _id: new ObjectId(id) }
      const result = await propertiesCollection.findOne(query)
      res.send(result)
    })

    // get properties by user use query
    app.get('/property/:email', async (req, res) => {
      const email = req.params.email
      const query = {agentEmail:email}
      const result = await propertiesCollection.find(query).toArray()
      res.send(result)
      
    })

    // update property status
    app.patch('/properties/:id', async (req, res) => {
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
    app.patch('/properties/:id/advertise', async (req, res) => {
      
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


    //get all wishlist
    app.get('/wishlist', async (req, res) => {
       const result = await wishlistCollection.find().toArray()
        res.send(result)
    }) 
     
    // get single wishlist
   

    // get wishlist by user 
    app.get('/wishlist/:email', async (req, res) => {
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
  

    // get all offers
    app.get('/offers', async (req, res) => {
      const email = req.query.email
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
    app.post('/offers', async (req, res) => {
      
      const offer = req.body
      const result = await offersCollection.insertOne(offer)
      res.send(result)
    })
  
  // update offer status

    app.patch('/offers/:id/accept', async (req, res) => {
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
  
    // reject offer

  app.patch('/offers/:id/reject', async (req, res) => {
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
    app.get('/allreviews/:email', async (req, res) => {
      const email = req.params.email
      const query = { userEmail: email }
      const result = await reviwesCollection.find(query).toArray()
      res.send(result)
    })

    // save review data in db
    app.post('/reviews', async (req, res) => {
      const review = req.body
      review.date = new Date()
      const result = await reviwesCollection.insertOne(review)
      res.send(result)
    })
  
    // delete a review
    app.delete('/reviews/:id', async (req, res) => {
      const id = req.params.id
      const query = { _id: new ObjectId(id) }
      const result = await reviwesCollection.deleteOne(query)
      res.send(result)
    })




    // Send a ping to confirm a successful connection
    await client.db('admin').command({ ping: 1 })
    console.log(
      'Pinged your deployment. You successfully connected to MongoDB!'
    )
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
