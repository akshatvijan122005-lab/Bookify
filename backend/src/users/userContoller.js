const jwt = require("jsonwebtoken");
const User = require("./usermodel");

const bcrypt = require("bcrypt");

module.exports.adminLogin = async (req,res)=>{
  const {username,password} = req.body;
  const jwtSecret = process.env.JWT_SECRET_KEY;

  try{
    const admin = await User.findOne({username, role:"admin"});
    if(!admin){
      return res.status(404).send({message:"Admin not found"});
    }

    const isMatch = await bcrypt.compare(password, admin.password);
    if(!isMatch){
      return res.status(401).send({message:"Invalid password"});
    }

    const token = jwt.sign(
      {id:admin._id, username:admin.username, role:admin.role},
      jwtSecret,
      {expiresIn:"1h"}
    );

    res.status(200).send({
      message:"Authentication successful",
      token,
      user:{
        username:admin.username,
        role:admin.role
      }
    });

  }catch(err){
    res.status(500).send({message:"Login failed"});
  }
}
