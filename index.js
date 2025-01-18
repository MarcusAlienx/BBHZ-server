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
   
    // save property data in db
    app.post('/properties', async (req, res) => {
      const property = req.body
      const result = await propertiesCollection.insertOne(property)
      res.send(result)
    })

    // get all properties
    app.get('/properties', async (req, res) => {
        
      const result = await propertiesCollection.find().toArray()
      res.send(result)
    })
    // get single property
    app.get('/properties/:id', async (req, res) => {
      const id = req.params.id
      const query = { _id: new ObjectId(id) }
      const result = await propertiesCollection.findOne(query)
      res.send(result)
    })

    // get properties by user use query
    app.get('/propertie/:email', async (req, res) => {
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
