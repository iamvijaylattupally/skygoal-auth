//importing required modules in es module
import express from "express";
import bodyParser from "body-parser"; 
import env from "dotenv";
import cookieParser from "cookie-parser";
import bcrypt from "bcrypt";
import { createToken , validateToken } from "./JWT.js";
import { MongoClient } from 'mongodb';

env.config(); 
// Connection URL
const url = process.env.MONGODB_URL
const client = new MongoClient(url);
const dbName = 'usersData';

const port = process.env.PORT;
const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser()); 


//Login route
app.post("/login",async(req,res)=>{
    const {email , password } = req.body;
    try{
        //connecting to the mongodb database
        await client.connect();
        const db = client.db(dbName);
        const collection = db.collection('documents');

        //checking if the user is not registered
        const filteredDocs = await collection.find({ email:email }).toArray();
        if(filteredDocs.length===0){
            res.status(400).json("user is not registered");
        }else{
            //validating password
            const storedPasssword=filteredDocs[0].password;
            const match = await bcrypt.compare(password,storedPasssword);
            if(match){
                const accessToken = createToken({email:email,password:storedPasssword});
                //creating a jsonwebtoken and storing it as httponly cookie for 1 hour in browser
                res.cookie("accessToken",accessToken,{
                    maxAge:1000*60*60,
                    httpOnly:true
                })
                console.log("Login sucessfull");
                res.redirect("/profile");
            }else{
                res.status(400).json("Password does not match")
            }
        }
    }catch(err){
        console.log(err);
    }
})

//registration route
app.post("/register",async(req,res)=>{
    const {email , password ,name,age } = req.body;
    //creating a hash password with bcrypt
    await bcrypt.hash(password,10).then(async(hash)=>{
        
        try{
            //connecting to the mongodb database
            await client.connect();
            const db = client.db(dbName);
            const collection = db.collection('documents');

            //checking if the user is already registered
            const filteredDocs = await collection.find({ email:email }).toArray();
            if(filteredDocs.length===0){
                //inserting document in databse
                const insertResult = await collection.insertOne({email:email,password:hash,name:name,age:age});
                console.log(`document is inseerted ${insertResult}`);

                //creating a jsonwebtoken and storing it as httponly cookie for 1 hour in browser
                const accessToken = createToken({email:email,password:hash});
                res.cookie("accessToken",accessToken,{
                    maxAge:1000*60*60,
                    httpOnly:true
                }) 
                console.log(`Registration succesfull`);
                res.redirect("/profile")
            }
            else{
                res.status(400).json("user is already registered")
            }
        }catch(err){
            console.log(err);
        }
    })
})

//user is redirected here after successfull login or sign up this is completely optional and depends on frontend client 
app.post("/profile",validateToken,(req,res)=>{ //validating jsonwebtoken
    console.log(req.authenticated);
    res.json("profile");
})

app.listen(port,()=>{
    console.log(`server is running in port ${port}`);
})