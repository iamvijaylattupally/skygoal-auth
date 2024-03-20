import jwt from "jsonwebtoken";
import env from "dotenv";

env.config();

export const createToken = (user)=>{
    const accessToken = jwt.sign(user,process.env.SECRET_KEY);
    return accessToken;
}

export  const validateToken = (req , res , next )=>{
    
    const accessToken = req.cookies["accessToken"];

    if(!accessToken){
        return res.status(400).json("user not authenticated");
    }
    try{
        const validToken = jwt.verify(accessToken,process.env.SECRET_KEY);
        if(validToken){
            req.authenticated = true;
            return next();
        }
        else{
            return res.status(400).json(err);
        }
    }catch(err){
        console.log(err);
        return res.status(400).json({error:err});
    }
}