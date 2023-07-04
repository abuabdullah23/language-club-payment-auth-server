require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const app = express();
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY)
const port = process.env.PORT || 5000;

// middleware
app.use(cors());
app.use(express.json());

// verify jwt token
const verifyJWT = (req, res, next) => {
    const authorization = req.headers.authorization;
    if (!authorization) {
        return res.status(401).send({ error: true, message: 'Unauthorized Access' });
    }
    // Bearer Token
    const token = authorization.split(' ')[1];

    // verify a token
    jwt.verify(token, process.env.ACCESS_SECRET_TOKEN, (error, decoded) => {
        if (error) {
            return res.status(401).send({ error: true, message: 'Unauthorized Access' });
        }
        req.decoded = decoded;
        next();
    })
}

// =========================  MongoDb =====================
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_SECRET}@cluster0.ufrxsge.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        client.connect();

        // create db
        const usersCollection = client.db('languageClub').collection('users');
        const classesCollection = client.db('languageClub').collection('classes');
        const cartCollection = client.db('languageClub').collection('cart');
        const paymentCollection = client.db('languageClub').collection('payment');

        // jwt create
        app.post('/jwt', (req, res) => {
            const user = req.body;
            const token = jwt.sign(user, process.env.ACCESS_SECRET_TOKEN, { expiresIn: '1h' })
            res.send({ token })
        })

        // verify Admin to secure Admin route
        const verifyAdmin = async (req, res, next) => {
            const email = req.decoded.email;
            const query = { email: email };
            const user = await usersCollection.findOne(query);
            if (user?.role !== 'admin') {
                return res.status(403).send({ error: true, message: 'Forbidden Access' });
            }
            next();
        }

        // verify Instructor to secure Instructor route
        const verifyInstructor = async (req, res, next) => {
            const email = req.decoded.email;
            const query = { email: email };
            const user = await usersCollection.findOne(query);
            if (user?.role !== 'instructor') {
                return res.status(403).send({ error: true, message: 'Forbidden Access' });
            }
            next();
        }

        // ================ Admin Api ===========================
        // to check this user admin or not.......
        app.get('/users/admin/:email', verifyJWT, async (req, res) => {
            const email = req.params.email;
            if (req.decoded.email !== email) {
                return res.send({ admin: false })
            }
            const query = { email: email }
            const user = await usersCollection.findOne(query);
            const result = { admin: user?.role === 'admin' }
            res.send(result);
        })
        // ================ Admin Api ===========================


        // ================ Instructor Api ======================
        // to check this user instructor or not.......
        app.get('/users/instructor/:email', verifyJWT, async (req, res) => {
            const email = req.params.email;
            if (req.decoded.email !== email) {
                return res.send({ admin: false })
            }
            const query = { email: email }
            const user = await usersCollection.findOne(query);
            const result = { admin: user?.role === 'instructor' }
            res.send(result);
        })
        // ================ Instructor Api ======================


        // ================ user related api =========================
        app.post('/users', async (req, res) => {
            const user = req.body;
            const query = { email: user.email } // for do not create duplicate
            const existingUser = await usersCollection.findOne(query);
            if (existingUser) {
                return res.send({ message: 'User already exists!' })
            }
            const result = await usersCollection.insertOne(user);
            res.send(result);
        })

        // get users api with jwt security
        app.get('/users', verifyJWT, verifyAdmin, async (req, res) => {
            const result = await usersCollection.find().toArray();
            res.send(result);
        })

        // get all instructor for display Instructor page
        app.get('/instructors', async (req, res) => {
            const query = { role: "instructor" };
            const result = await usersCollection.find(query).toArray();
            res.send(result);
        })

        // get popular instructor for display Home page
        app.get('/instructors/popular', async (req, res) => {
            const query = { role: "instructor" };
            const result = await usersCollection.find(query).toArray();
            res.send(result);
        })

        // delete users method with jwt security
        app.delete('/users/:id', verifyJWT, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const result = await usersCollection.deleteOne(query);
            res.send(result);
        })

        // create admin method from user list with jwt
        app.patch('/users/admin/:id', verifyJWT, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const filter = { _id: new ObjectId(id) };
            const updateDoc = {
                $set: {
                    role: 'admin'
                },
            };
            const result = await usersCollection.updateOne(filter, updateDoc);
            res.send(result);
        })

        // create instructor method from user list with jwt
        app.patch('/users/instructor/:id', verifyJWT, async (req, res) => {
            const id = req.params.id;
            const filter = { _id: new ObjectId(id) };
            const updateDoc = {
                $set: {
                    role: 'instructor'
                },
            };
            const result = await usersCollection.updateOne(filter, updateDoc);
            res.send(result);
        })

        // =============== Class related Api ==============
        app.post('/classes', verifyJWT, verifyInstructor, async (req, res) => {
            const addClass = req.body;
            const result = await classesCollection.insertOne(addClass);
            res.send(result);
        })

        // get all classes method for admin
        app.get('/classes', verifyJWT, verifyAdmin, async (req, res) => {
            const result = await classesCollection.find().toArray();
            res.send(result);
        })

        // get all classes with specific properties for normal user
        app.get('/classes/user', async (req, res) => {
            const query = { price: { $gt: 10 } };
            const options = {
                sort: { enrolled: -1 },
                projection: { _id: 1, name: 1, image: 1, instructorName: 1, seats: 1, status: 1, price: 1, enrolled: 1 },
            };
            const result = await classesCollection.find(query, options).toArray();
            res.send(result);
        })

        // get only Approved popular class with specific properties for general user
        app.get('/classes/popular', async (req, res) => {
            const query = { status: "Approved" };
            const options = {
                sort: { enrolled: -1 },
                projection: { _id: 1, name: 1, image: 1, instructorName: 1, seats: 1, status: 1, price: 1, enrolled: 1 },
            };
            const result = await classesCollection.find(query, options).toArray();
            res.send(result);
        })

        // ============= Cart in class related api ==============
        app.post('/cart', verifyJWT, async (req, res) => {
            const addCart = req.body;
            const result = await cartCollection.insertOne(addCart);
            res.send(result)
        })

        app.get('/carts', verifyJWT, async (req, res) => {
            const email = req.query.email;
            if (!email) {
                return res.send([])
            }
            const decodedEmail = req.decoded.email;
            if (email !== decodedEmail) {
                return res.status(403).send({ error: true, message: 'Forbidden Access!' })
            }

            const query = { email: email }
            const result = await cartCollection.find(query).toArray();

            res.send(result);
        })

        app.delete('/carts/delete/:id', verifyJWT, async (req, res) => {
            const id = req.params.id;
            const filter = { _id: new ObjectId(id) };
            const result = await cartCollection.deleteOne(filter);
            res.send(result);
        })

        // get single cart info for payment
        app.get('/cart/:id', verifyJWT, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) }
            const result = await cartCollection.findOne(query);
            res.send(result);
        })

        // create payment intent
        app.post('/create-payment-intent', verifyJWT, async (req, res) => {
            const { price } = req.body;
            // console.log(price)
            const amount = parseInt(price * 100); // fixed invalid integer
            // console.log(price, amount)
            const paymentIntent = await stripe.paymentIntents.create({
                amount: amount,
                currency: 'usd',
                payment_method_types: ['card']
            });
            res.send({
                clientSecret: paymentIntent.client_secret
            })
        })

        // payment related api
        app.post('/payments', verifyJWT, async (req, res) => {
            const payment = req.body;
            const insertResult = await paymentCollection.insertOne(payment);
            res.send(insertResult)
        })

        // get payment api
        app.get('/payments', verifyJWT, async (req, res) => {
            const email = req.query.email;
            if (!email) {
                return res.send([])
            }
            const decodedEmail = req.decoded.email;
            if (email !== decodedEmail) {
                return res.status(403).send({ error: true, message: 'Forbidden Access!' })
            }
            const query = { email: email }

            // sorting by date
            const options = {
                sort: { date: -1 }
            }
            const result = await paymentCollection.find(query, options).toArray();

            res.send(result);
        })



        // ============= Cart in class related api ==============

        // delete class method for Admin
        app.delete('/classes/:id', verifyJWT, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const result = await classesCollection.deleteOne(query);
            res.send(result);
        })

        // delete class method for Instructor
        app.delete('/classes/delete/byInstructor/:id', verifyJWT, verifyInstructor, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const result = await classesCollection.deleteOne(query);
            res.send(result);
        })

        // get class method for instructor by his email, He will see only his added class, it will verifyInstructor
        app.get('/classes/instructor', verifyJWT, verifyInstructor, async (req, res) => {
            let query = {};
            if (req.query?.email) {
                query = { email: req.query.email }
            }
            const result = await classesCollection.find(query).toArray();
            res.send(result);
        })

        // get class for display by id in "update class info" route
        app.get('/class/display/:id', async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const result = await classesCollection.findOne(query);
            res.send(result);
        })

        // Update Class method by instructor
        app.put('/class/update/:id', verifyJWT, verifyInstructor, async (req, res) => {
            const id = req.params.id;
            const updatedClass = req.body;
            const filter = { _id: new ObjectId(id) };
            const options = { upsert: true };
            const updateDoc = {
                $set: {
                    name: updatedClass.name,
                    seats: updatedClass.seats,
                    price: updatedClass.price,
                    status: "Pending"
                }
            }
            const result = await classesCollection.updateOne(filter, updateDoc, options); // options will be las
            res.send(result);
        })

        // approve class method by admin
        app.patch('/classes/approve/:id', verifyJWT, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const filter = { _id: new ObjectId(id) }
            const updateDoc = {
                $set: {
                    status: 'Approved'
                },
            };
            const result = await classesCollection.updateOne(filter, updateDoc);
            res.send(result);
        })

        // Deny class method by admin
        app.patch('/classes/deny/:id', verifyJWT, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const filter = { _id: new ObjectId(id) }
            const updateDoc = {
                $set: {
                    status: 'Denied'
                },
            };
            const result = await classesCollection.updateOne(filter, updateDoc);
            res.send(result);
        })

        // Feedback in denied/approved class method by admin
        app.get('/dashboard/admin-feedback/:id', async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const result = await classesCollection.findOne(query);
            res.send(result);
        })

        // send feedback method
        app.put('/classes/feedback/:id', verifyJWT, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const updatedFeedback = req.body;
            const filter = { _id: new ObjectId(id) };
            const options = { upsert: true };
            const sendFeedback = {
                $set: {
                    feedback: updatedFeedback.feedback
                }
            }
            const result = await classesCollection.updateOne(filter, sendFeedback, options); // options will be las
            res.send(result);
        })
        // =============== Class related Api ==============




        // Send a ping to confirm a successful connection
        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);

// =========================  MongoDb =====================

app.get('/', (req, res) => {
    res.send('Language Club Server is Running');
})

app.listen(port, () => {
    console.log('Language club server is running on port:', port);
})