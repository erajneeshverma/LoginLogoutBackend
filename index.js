import express from 'express'
const app = express();
import path from 'path';
import mongoose from 'mongoose';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';


app.set("view engine","ejs");

app.use(express.static(path.join(path.resolve(),"public")));

app.use(express.urlencoded({extended:true}));

app.use(cookieParser());


mongoose.connect("mongodb://localhost:27017",{
    dbName: "backend",
}).then(()=> console.log("Database Connected")).catch((e)=>{
    console.log("Connection Error : ",e);
})

const userSchema = mongoose.Schema({
    name:{
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
    },
    password:{
        type: String,
        required: true,
    },
},{timestamps:true})

const User = mongoose.model("User",userSchema);





const isAuthenticated = async (req,res,next)=>{

    const {token} = req.cookies;
    
    if(token){
        const decoded = jwt.verify(token,"qwertuiopasdfghjklzxcvbnm");
        req.user = await User.findById(decoded._id);
        next();
    }else{
        res.redirect("login")
    }
}

app.get("/", isAuthenticated, (req,res)=>{
    //console.log(req.user)
    res.render("logout",{name: req.user.name,email:req.user.email});
}) 

app.post("/login", async (req,res)=>{
    const {email,password} = req.body;

    const user = await User.findOne({email});
    if(!user){
        return res.redirect("/register");
    }

    const isMatch = await bcrypt.compare(password,user.password);

    console.log(user);
    if(user.email==email && isMatch===true){
        const token = jwt.sign({_id:user._id},"qwertuiopasdfghjklzxcvbnm");
        res.cookie("token",token,{
            httpOnly:true,
            expires: new Date(Date.now()+60*1000)
        });
        res.redirect("/");
    }else{
        res.render("login",{email,message:"Incorrect Password!!"});
    }
})

app.get("/register", (req,res)=>{
    //console.log(req.user)
    res.render("register");
}) 

app.get("/login", (req,res)=>{
    //console.log(req.user)
    res.render("login");
}) 

app.post("/register", async (req,res)=>{
    //console.log(req.body)
    const {name,email,password} = req.body;

    let user = await User.findOne({email});
    if(user){
        console.log("already Logged in....");
        return res.redirect("/login");
    }

    const hashedPassword = await bcrypt.hash(password,10);

    user = await User.create({
        name,
        email,
        password: hashedPassword,
    })

    
    const token = jwt.sign({_id:user._id},"qwertuiopasdfghjklzxcvbnm");
    res.cookie("token",token,{
        httpOnly:true,
        expires: new Date(Date.now()+60*1000)
    });
    res.redirect("/")
})

app.get("/logout",(req,res)=>{
    res.cookie("token",null, {
        expires: new Date(Date.now())
    })
    res.redirect("/")
})

app.listen(5000,()=>{
    console.log("Server is running...")
})