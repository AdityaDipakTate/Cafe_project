const express = require("express");
const router = express.Router();
const Users = require("../../database/models").user;
const Joi = require("joi");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const jwtSecretKey = process.env.JWT_SECRET_KEY;

const usernameSchema = Joi.string().min(4).required();
const passwordSchema = Joi.string()
  .min(8)
  .pattern(new RegExp("^(?=.*[A-Z])"))
  .message({
    "string.min": "Password must have at least 8 characters",
    "string.pattern.base": "Password must contain at least one capital letter",
  })
  .pattern(new RegExp("^(?=.*[0-9])"))
  .message({
    "string.pattern.base": "Password must contain at least one number",
  })
  .pattern(new RegExp("^(?=.*[!@#$%^&*])"))
  .message({
    "string.pattern.base":
      "Password must contain at least one special character",
  })
  .required();

const confirmPasswordSchema = Joi
  .string()
  .valid(Joi.ref("password"))
  .required()
  .messages({
    "any.only": "Passwords don't match",
  });

  // Route for user login
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ where: { username } });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: 'Incorrect password' });
    }
    // Generate JWT token for authentication
    const token = jwt.sign({ userId: user.id }, jwtSecretKey);
    res.json({ token });
  } catch (error) {
    console.error('Error logging in:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Add more routes for authentication-related operations...



  
module.exports = router;
