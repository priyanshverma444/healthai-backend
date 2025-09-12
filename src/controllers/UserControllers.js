const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const nodemailer = require('nodemailer');
const cloudinary = require('cloudinary').v2;
const frontendUrl = process.env.FRONTEND_URI || "http://localhost:3000";

//@desc Get all Users
//@route Get /api/users
//@access public
const getUsers = asyncHandler(async (req, res) => {
  const apiKey = req.headers.authorization;
  if (apiKey !== `Bearer ${process.env.API_KEY}`) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  const users = await User.find();

  res.status(200).json(users);
});

// @desc get Users
// @route GET /api/users/:id
// @access public
const getUser = asyncHandler(async (req, res) => {
  const apiKey = req.headers.authorization;
  if (apiKey !== `Bearer ${process.env.API_KEY}`) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const user = await User.findById(req.params.id);
  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }
  res.status(200).json(user);
});

//@desc update Users
//@route PUT /api/users/:id
//@access public
const updateUser = asyncHandler(async (req, res) => {
  const apiKey = req.headers.authorization;
  if (apiKey !== `Bearer ${process.env.API_KEY}`) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const user = await User.findById(req.params.id);
  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }
  const updatedUser = await User.findByIdAndUpdate(req.params.id, req.body, {
    new: true,
  });

  res.status(200).json(updatedUser);
});

//@desc Register a user
//@route POST /api/users/register
//@access public
const registerUser = asyncHandler(async (req, res) => {
  const apiKey = req.headers.authorization;
  if (apiKey !== `Bearer ${process.env.API_KEY}`) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  try {
    const {
      username,
      dob,
      gender,
      email,
      address,
      city,
      pincode,
      password,
      bio
    } = req.body;

    // Check if the user is already registered
    const userAvailable = await User.findOne({ email });
    if (userAvailable) {
      return res.status(409).json({ 
        error: "User already exists", 
        message: "An account with this email address already exists. Please use a different email or sign in to your existing account.",
        action: "redirect_to_login",
        loginUrl: "/login" // You can customize this based on your frontend routing
      });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log("Hashed Password: ", hashedPassword);

    // Create the user
    const user = await User.create({
      username,
      dob,
      gender,
      email,
      address,
      city,
      pincode,
      password: hashedPassword,
      bio
    });

    const accessToken = jwt.sign(
      {
        user: {
          id: user.id,
          username: user.username,
          dob: user.dob,
          gender: user.gender,
          email: user.email,
          address: user.address,
          city: user.city,
          pincode: user.pincode,
          bio: user.bio
        },
      },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: "1d" }
    );

    // Send a success response
    return res
      .status(201) // Changed to 201 for resource creation
      .json({ 
        message: "User registered successfully", 
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          // Don't send sensitive data like password
        }, 
        accessToken 
      });
  } catch (error) {
    // Handle any errors that occur during registration
    console.error("Error:", error);
    return res.status(500).json({ 
      error: "Registration failed",
      message: "An error occurred during registration. Please try again.",
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

//@desc Login user
//@route POST /api/users/login
//@access public
const loginUser = asyncHandler(async (req, res) => {
  const apiKey = req.headers.authorization;
  if (apiKey !== `Bearer ${process.env.API_KEY}`) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      res.status(400);
      throw new Error("All fields are mandatory!");
    }
    const user = await User.findOne({ email });

    if (user && (await bcrypt.compare(password, user.password))) {
      const accessToken = jwt.sign(
        {
          user: {
            id: user.id,
            username: user.username,
            dob: user.dob,
            gender: user.gender,
            email: user.email,
            address: user.address,
            city: user.city,
            pincode: user.pincode,
            bio: user.bio
          },
        },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: "1d" }
      );
      res.status(200).json({ accessToken });
    } else {
      res.status(401);
      throw new Error("Email or password is not valid");
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const updateUserImage = async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }

    const result = await cloudinary.uploader.upload(
      `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}`,
      {
        folder: 'user_profile_images', 
      }
    );

    user.userImage = result.secure_url;
    await user.save();

    res.status(200).json({ userImage: user.userImage });
  } catch (error) {
    console.error('Error uploading image:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// HTML Email Template for VedaBot
const getEmailTemplate = (resetUrl) => {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Your VedaBot Password</title>
    <style>
        body {
            margin: 0;
            padding: 0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f5f5f5;
            line-height: 1.6;
        }
        
        .email-container {
            max-width: 600px;
            margin: 0 auto;
            background-color: #AFD9B1;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
        }
        
        .email-header {
            text-align: center;
            padding: 40px 20px 20px;
            background: linear-gradient(135deg, #AFD9B1 0%, #9BC7A0 100%);
        }
        
        .logo {
            background-color: #065f46;
            color: white;
            width: 60px;
            height: 60px;
            border-radius: 50%;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 20px;
            box-shadow: 0 4px 12px rgba(6, 95, 70, 0.3);
        }
        
        .email-title {
            color: #065f46;
            font-size: 28px;
            font-weight: 700;
            margin: 0;
            text-shadow: 0 1px 2px rgba(255, 255, 255, 0.3);
        }
        
        .email-body {
            padding: 40px 30px;
            background-color: #AFD9B1;
            color: #065f46;
        }
        
        .greeting {
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 20px;
        }
        
        .message {
            font-size: 16px;
            margin-bottom: 30px;
            color: #047857;
        }
        
        .reset-button {
            display: inline-block;
            background: linear-gradient(135deg, #065f46 0%, #047857 100%);
            color: white !important;
            text-decoration: none;
            padding: 16px 32px;
            border-radius: 8px;
            font-weight: 600;
            font-size: 16px;
            text-align: center;
            margin: 20px 0;
            box-shadow: 0 4px 12px rgba(6, 95, 70, 0.3);
        }
        
        .button-container {
            text-align: center;
            margin: 30px 0;
        }
        
        .expiry-notice {
            background-color: rgba(6, 95, 70, 0.1);
            padding: 15px 20px;
            margin: 25px 0;
            border-radius: 0 8px 8px 0;
            font-size: 14px;
            color: #065f46;
        }
        
        .alternative-text {
            font-size: 14px;
            color: #047857;
            margin-top: 30px;
            line-height: 1.5;
        }
        
        .alternative-link {
            color: #065f46;
            word-break: break-all;
            font-family: monospace;
            background-color: rgba(255, 255, 255, 0.3);
            padding: 8px 12px;
            border-radius: 4px;
            display: inline-block;
            margin: 10px 0;
            font-size: 12px;
        }
        
        .email-footer {
            background-color: rgba(6, 95, 70, 0.1);
            padding: 30px;
            text-align: center;
            color: #065f46;
            font-size: 14px;
        }
        
        .footer-links {
            margin-top: 20px;
        }
        
        .footer-links a {
            color: #065f46;
            text-decoration: none;
            margin: 0 15px;
            font-weight: 500;
        }
        
        .security-notice {
            background-color: rgba(6, 95, 70, 0.05);
            border-radius: 8px;
            padding: 20px;
            margin: 25px 0;
            font-size: 14px;
            color: #065f46;
        }
        
        @media (max-width: 600px) {
            .email-container {
                margin: 10px;
                border-radius: 8px;
            }
            
            .email-body {
                padding: 20px;
            }
            
            .email-title {
                font-size: 24px;
            }
            
            .reset-button {
                padding: 14px 28px;
                font-size: 15px;
            }
        }
    </style>
</head>
<body>
    <div class="email-container">
        <!-- Header -->
        <div class="email-header">
            <h1 class="email-title">VedaBot</h1>
        </div>
        
        <!-- Body -->
        <div class="email-body">
            <div class="greeting">Hello there! 👋</div>
            
            <div class="message">
                We received a request to reset the password for your VedaBot account. If you made this request, click the button below to create a new password.
            </div>
            
            <div class="button-container">
                <a href="${resetUrl}" class="reset-button">Reset Your Password</a>
            </div>
            
            <div class="expiry-notice">
                <span style="margin-right: 8px;">⏰</span>
                <strong>Important:</strong> This password reset link will expire in 1 hour for your security.
            </div>
            
            <div class="security-notice">
                <span style="margin-right: 8px;">🔒</span>
                <strong>Security Tip:</strong> If you didn't request this password reset, you can safely ignore this email. Your account remains secure and no changes have been made.
            </div>
            
            <div class="alternative-text">
                If the button above doesn't work, you can copy and paste this link into your browser:
                <div class="alternative-link">${resetUrl}</div>
            </div>
        </div>
        
        <!-- Footer -->
        <div class="email-footer">
            <div>
                <strong>VedaBot Team</strong><br>
                Take your health into your own hands
            </div>
            
            <div style="margin-top: 20px; font-size: 12px; opacity: 0.8;">
                © 2025 VedaBot. All rights reserved.
            </div>
        </div>
    </div>
</body>
</html>
  `;
};

// @desc Forgot Password
// @route POST /api/users/forgot-password
// @access public
const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });

  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }

  const resetToken = jwt.sign(
    { id: user._id },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: '1h' }
  );

  const encodedToken = encodeURIComponent(resetToken);
  const resetUrl = `${frontendUrl}/reset-password?token=${encodedToken}`;
  
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  const mailOptions = {
    from: `"VedaBot Team" <${process.env.EMAIL_USER}>`,
    to: user.email,
    subject: 'Reset Password for VedaBot',
    html: getEmailTemplate(resetUrl),
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      return res.status(500).json({ message: 'Email could not be sent' });
    }
    res.status(200).json({ message: 'Password reset email sent' });
  });
});

// @desc Reset Password
// @route POST /api/users/reset-password/:token
// @access public
const resetPassword = asyncHandler(async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  try {
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    const user = await User.findById(decoded.id);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    user.password = hashedPassword;
    await user.save();

    res.status(200).json({ message: 'Password reset successful' });
  } catch (error) {
    res.status(400).json({ message: 'Invalid or expired token' });
  }
});

module.exports = {
  registerUser,
  loginUser,
  getUsers,
  getUser,
  updateUser,
  forgotPassword,
  resetPassword,
  updateUserImage
};
