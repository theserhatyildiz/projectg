const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const sanitizeHtml = require('sanitize-html');
const { body, validationResult, param } = require('express-validator');
require('dotenv').config();
const crypto = require('crypto');
const path = require('path');

const userModel = require('./models/userModel')
const foodModel =  require('./models/foodModel')
const userFoodModel = require('./models/userFoodModel')
const trackingModel = require('./models/trackingModel')
const verifyToken = require('./verifyToken')
const weightModel = require('./models/weightModel');
const refreshTokenModel = require('./models/refreshTokenModel'); 

// database connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.log(err.message));

const app = express();
app.use(helmet());
app.use(cors({
  origin: 'http://localhost:5173', // Allow requests from this origin
  credentials: true, // Allow cookies and other credentials to be sent
  allowedHeaders: ['Content-Type', 'csrf-token', 'Authorization'], // Allow csrf-token and Authorization headers
}));
app.use(express.json());
app.use(cookieParser());
app.use(csrf({ cookie: true }));

// Rate limiting
// const limiter = rateLimit({
//   windowMs: 15 * 60 * 1000,
//   max: 100,
//   message: "Too many requests, please try again later."
// });
// app.use(limiter);

app.use((req, res, next) => {
  res.cookie('XSRF-TOKEN', req.csrfToken());
  next();
});

app.get('/csrf-token', (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

// Sanitize a string input using sanitize-html
const sanitizeInput = (input) => sanitizeHtml(input, {
  allowedTags: [],
  allowedAttributes: {}
});

///////////////////////////////////// REGISTER and LOGIN /////////////////////////////////////

// Endpoint to register a new user

app.post('/register', [
    body('name').isAlphanumeric().withMessage('Invalid username format.'),
    body('email').isEmail().withMessage('Invalid email format.'),
    body('password').isLength({ min: 11 }).withMessage('Password must be at least 11 characters long.')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  let user = req.body;

  try {
    const existingUser = await userModel.findOne({ name: user.name });
    if (existingUser) {
      return res.status(400).send({ message: 'Kullanıcı adı zaten kayıtlı!' });
    }

    const existingEmail = await userModel.findOne({ email: user.email });
    if (existingEmail) {
      return res.status(400).send({ message: 'Email zaten kayıtlı!' });
    }

    const salt = await bcrypt.genSalt(12);
    const hashedPassword = await bcrypt.hash(user.password, salt);
    user.password = hashedPassword;

    const emailToken = jwt.sign({ email: user.email }, process.env.JWT_SECRET, { expiresIn: '1d' });
    user.emailToken = emailToken;
    user.isVerified = false;

    const doc = await userModel.create(user);

    const transporter = nodemailer.createTransport({
      service: 'outlook',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
      }
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: 'Email Verification',
      html: `<p>Merhaba ${user.name},</p>
             <p>E-posta adresinizi doğrulamak için lütfen aşağıdaki bağlantıya tıklayın:</p>
             <p>http://localhost:5173/verify/${doc._id}/${emailToken}</p>
             <p><strong>Galwin Support Team</strong></p>`
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Error sending email:', error);
        return res.status(500).send({ message: 'Email sending failed' });
      } else {
        console.log('Email sent: ' + info.response);
        res.status(201).send({ message: "Üyelik Oluşturuldu! Lütfen e-posta adresinizi doğrulamak için gelen kutunuzu kontrol edin." });
      }
    });
  } catch (err) {
    console.error('Error registering user:', err);
    res.status(500).send({ message: 'An error occurred during registration. Please try again later.' });
  }
});

app.post('/verify/:id/:token', async (req, res) => {
  const { id, token } = req.params;
  const csrfToken = req.headers['csrf-token'];
  const csrfTokenFromCookie = req.cookies['XSRF-TOKEN'];

  if (!csrfToken || csrfToken !== csrfTokenFromCookie) {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await userModel.findById(id);

    if (!user || user.email !== decoded.email) {
      return res.status(400).json({ message: 'Invalid token or user.' });
    }

    user.isVerified = true;
    user.emailToken = null;
    await user.save();

    res.status(200).json({ message: 'Email successfully verified.' });
  } catch (err) {
    console.error('Error verifying email:', err);
    res.status(500).json({ message: 'Email verification failed.' });
  }
});

// Endpoint to login a user
app.post('/login', async (req, res) => {
  let userCred = req.body;
  console.log('Login attempt:', userCred);

  try {
    const user = await userModel.findOne({ email: userCred.email });
    if (user) {
      console.log('User found:', user.email);

      const match = await bcrypt.compare(userCred.password, user.password);
      if (match) {
        console.log('Password match successful');

        // Generate access token (expires in 15 minutes for production)
        const token = jwt.sign({ email: user.email, userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1m' });

         // Generate refresh token and save it to the database (expires in 7 days for production)
        const expiryDate = new Date(Date.now() + 5 * 60 * 1000); // 2 minutes from now
        const newRefreshToken = new refreshTokenModel({
          token: crypto.randomBytes(40).toString('hex'),
          userId: user._id,
          expiryDate: expiryDate
        });
        await newRefreshToken.save(); // Save refresh token to DB

        console.log('Generated access token:', token);
        console.log('Generated refresh token and stored in DB:', newRefreshToken.token);

        // Set the refresh token in a cookie (httpOnly, secure, etc.)
        res.cookie('refreshToken', newRefreshToken.token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'Strict',
          maxAge: 5 * 60 * 1000 // 2 minutes in milliseconds
        });

        res.send({
          message: "Login Success",
          token: token,
          userid: user._id,
          name: user.name,
          isVerified: user.isVerified,
          email: user.email
        });
      } else {
        console.log('Invalid password');
        res.status(403).send({ message: "Invalid Password" });
      }
    } else {
      console.log('User not found');
      res.status(404).send({ message: "User not found" });
    }
  } catch (err) {
    console.error('Error Finding User:', err);
    res.status(500).send("Internal Server Error");
  }
});


// Endpoint to refresh the access token bu storedToken.remove is not a function hatasi veren
app.post('/refresh-token', async (req, res) => {
  console.log('Received cookies:', req.cookies);
  console.log('Req Body:', req.body);

  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) {
    console.log('No refresh token provided');
    return res.status(401).send({ message: "No refresh token provided" });
  }

  try {
    // Find the refresh token in the database
    const storedToken = await refreshTokenModel.findOne({ token: refreshToken });
    if (!storedToken) {
      console.log('Invalid or expired refresh token');
      return res.status(403).send({ message: "Invalid refresh token" });
    }

    // Generate a new access token (expires in 1 minute for testing)
    const newToken = jwt.sign(
      { email: storedToken.email, userId: storedToken.userId },
      process.env.JWT_SECRET,
      { expiresIn: '1m' }
    );
    console.log('Generated new access token:', newToken);

    // Check if the refresh token is close to expiration, if so, generate a new one
    const now = Date.now();
    const timeRemaining = storedToken.expiryDate - now;
    if (timeRemaining < 2 * 60 * 1000) { // Less than 1 minute remaining
      const newExpiryDate = new Date(now + 5 * 60 * 1000); // Extend by 2 more minutes
      const newRefreshToken = new refreshTokenModel({
        token: crypto.randomBytes(40).toString('hex'),
        userId: storedToken.userId,
        expiryDate: newExpiryDate
      });

      await newRefreshToken.save(); // Save new token
      await refreshTokenModel.deleteOne({ _id: storedToken._id }); // Delete the old token

      console.log('Generated new refresh token:', newRefreshToken.token);

      res.cookie('refreshToken', newRefreshToken.token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'Strict',
        maxAge: 5 * 60 * 1000 // 2 minutes in milliseconds
      });

      res.send({ token: newToken });
    } else {
      console.log('Refresh token is still valid');
      res.send({ token: newToken });
    }
  } catch (err) {
    console.error('Error refreshing token:', err.message);
    res.status(500).send({ message: "Internal Server Error" });
  }
});

// Endpoint to logout a user
app.post('/logout', async (req, res) => {
  console.log('Logout request received');

  try {
    const refreshToken = req.cookies.refreshToken;
    if (refreshToken) {
      // If tokens are stored in raw format
      await refreshTokenModel.deleteOne({ token: refreshToken }); // Remove token from DB
      console.log('Refresh token removed from DB');
    }

    // Clear the refresh token cookie
    res.clearCookie('refreshToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'Strict'
    });

    res.send({ message: "Logged out successfully" });
  } catch (err) {
    console.error('Error during logout:', err.message);
    res.status(500).send({ message: "Internal Server Error" });
  }
});

// Endpoint for forgotpassword

app.post('/forgotpassword', async (req, res) => {
  const { email } = req.body;

  try {
    const user = await userModel.findOne({ email });
    if (!user) {
      return res.status(404).send({ Status: "User not existed" });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    const transporter = nodemailer.createTransport({
      service: 'outlook',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
      }
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Şifre Yenileme Linki',
      html: `<p><strong>Galwin App şifreniz sıfırlanmak istendi!</strong></p>
             <p>Eğer şifre yenileme talebinde bulunmadıysanız, bu e-postayı dikkate almayınız.</p>
             <p>Eğer şifre yenileme talebinde bulunduysanız şifrenizi değiştirmek için alttaki bağlantıya tıklayın.</p>
             <p>Galwin App şifre yenileme linkiniz: http://localhost:5173/resetpassword/${user._id}/${token}</p>
             <p><strong>Galwin Support Team</strong></p>`
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Error sending email:', error);
        return res.status(500).send({ Status: "Email sending failed" });
      } else {
        console.log('Email sent: ' + info.response);
        res.send({ Status: "Success" });
      }
    });
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).send({ Status: "Internal Server Error" });
  }
});

app.post('/resetpassword/:id/:token', async (req, res) => {
  const { id, token } = req.params;
  const { password } = req.body;

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.id !== id) {
      return res.status(403).json({ Status: "Invalid token" });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const user = await userModel.findByIdAndUpdate(id, { password: hashedPassword });

    if (!user) {
      return res.status(404).json({ Status: "User not found" });
    }

    res.json({ Status: "Success" });
  } catch (err) {
    console.error('Error resetting password:', err);
    res.status(500).send({ Status: "Error resetting password" });
  }
});

///////////////////////////////////// FETCH and SEARCH FOOD /////////////////////////////////////

// endpoint to fetch all foods

app.get("/foods", verifyToken, async (req, res) => {
    try {
        // Fetch all the food items created by the user
        let userFoods = await foodModel.find({ userId: req.userId });

        // Fetch all the food items from the default food database
        let defaultFoods = await foodModel.find({ userId: { $exists: false } });

        // Combine the default food items and user food items into a single array
        let foods = [...defaultFoods, ...userFoods];

        // Remove any duplicate food items based on the NameTr field
        foods = foods.filter((value, index, self) =>
            index === self.findIndex((t) => t.NameTr === value.NameTr)
        );

        res.send(foods);
    } catch (err) {
        console.log(err);
        res.status(500).send({ message: 'Some problem while getting nutrition info' });
    }
});

// end point for search food by name

// Improved Turkish-insensitive regex function
function turkishInsensitiveRegex(searchQuery) {
    const charMap = {
        'ı': '[ıiIİ]',
        'i': '[ıiIİ]',
        'I': '[ıiIİ]',
        'İ': '[ıiIİ]',
        'ü': '[üuÜU]',
        'u': '[uüUÜ]',
        'U': '[uüUÜ]',
        'Ü': '[üuÜU]',
        'ö': '[öoÖO]',
        'o': '[oöOÖ]',
        'O': '[oöOÖ]',
        'Ö': '[öoÖO]',
        'ş': '[şsŞS]',
        's': '[sşSŞ]',
        'S': '[sşSŞ]',
        'Ş': '[şsŞS]',
        'ç': '[çcÇC]',
        'c': '[cçCÇ]',
        'C': '[cçCÇ]',
        'Ç': '[çcÇC]',
        'ğ': '[ğgĞG]',
        'g': '[gğGĞ]',
        'G': '[gğGĞ]',
        'Ğ': '[ğgĞG]'
    };

    const regexStr = searchQuery.split('').map(char => charMap[char] || char).join('');
    return new RegExp(regexStr, 'i');
}

app.get('/foods/:name', 
  [
    param('name')
    .trim()
    .matches(/^[a-zA-ZıİşŞğĞüÜöÖçÇ\s]+$/)
    .withMessage('Invalid query parameter: Only letters and spaces are allowed')
    .isLength({ max: 50 })  // Add a maxLength of 50 characters
    .withMessage('Name parameter cannot exceed 50 characters')
    .customSanitizer(value => sanitizeHtml(value)),
  ], 
  verifyToken, 
  async (req, res) => {
      try {
          const errors = validationResult(req);
          if (!errors.isEmpty()) {
              return res.status(400).json({ errors: errors.array() });
          }
          
          const regexPattern = turkishInsensitiveRegex(sanitizeHtml(req.params.name));

          let userFoods = await foodModel.find({ 
              NameTr: { $regex: regexPattern },
              userId: req.userId
          });

          let defaultFoods = await foodModel.find({ 
              NameTr: { $regex: regexPattern },
              userId: { $exists: false }
          });

          let foods = [...userFoods, ...defaultFoods];

          if (foods.length !== 0) {
              res.send(foods);
          } else {
              res.status(404).send({ message: 'Food item not found' });
          }
      } catch (err) {
          console.log(err);
          res.status(500).send({ message: 'Some problem in getting the food using search' });
      }
});

app.get('/userfoods/:name', 
  [
    param('name')
    .trim()
    .matches(/^[a-zA-ZıİşŞğĞüÜöÖçÇ\s]+$/)
    .withMessage('Invalid query parameter: Only letters and spaces are allowed')
    .isLength({ max: 50 })  // Add a maxLength of 50 characters
    .withMessage('Name parameter cannot exceed 50 characters')
    .customSanitizer(value => sanitizeHtml(value)),
  ], 
  verifyToken, 
  async (req, res) => {
      try {
          const errors = validationResult(req);
          if (!errors.isEmpty()) {
              return res.status(400).json({ errors: errors.array() });
          }
          
          const regexPattern = turkishInsensitiveRegex(sanitizeHtml(req.params.name));

          const userFoods = await userFoodModel.find({
              NameTr: { $regex: regexPattern },
              userId: req.userId
          });

          if (userFoods.length !== 0) {
              res.json(userFoods);
          } else {
              res.status(404).json({ message: 'User food item not found' });
          }
      } catch (err) {
          console.error(err);
          res.status(500).json({ message: 'Some problem in getting the user food using search' });
      }
});

// end point to fetch all foods eaten by a user

app.get("/track/:userid/:date",verifyToken,async(req,res)=>{

    let userid = req.params.userid ; 
    let date = new Date(req.params.date).toLocaleDateString();

    try
    {

        let foods = await trackingModel.find({userId:userid,eatenDate:date});
        res.send(foods);

    }
    catch(err)
    {
        console.log(err);
        res.status(500).send({message:'Some problem in fetching all foods eaten by a user'})
    }
})

///////////////////////////////////// DELETE and CREATE FOOD /////////////////////////////////////

// Endpoint to delete a specific food entry

app.delete("/track/:id", verifyToken, async (req, res) => {
    const id = req.params.id; // Using the route parameter 'id' to represent the unique identifier (_id)
    console.log("Deleting food entry with id:", id);
  
    try {
      // Check if the food entry exists
      const foodEntry = await trackingModel.findById(id);
  
      if (!foodEntry) {
        console.log("Food entry not found");
        return res.status(404).send({ message: "Food entry not found" });
      }
  
      console.log("Deleting food entry from database");
      await trackingModel.deleteOne({ _id: id }); // Deleting the food entry based on its _id
      console.log("Food entry deleted");
  
      // Send a success response
      res.send({ message: "Food entry deleted successfully" });
    } catch (error) {
      console.error("Error deleting food entry:", error);
      res.status(500).send({ message: "An error occurred while deleting the food entry" });
    }
});

// end point to create a new food

app.post(
  "/foods",
  verifyToken,
  [
    // Validation and sanitization rules

    // Sanitize and validate name: string, required, max length 6
    body('NameTr')
      .trim()  // Removes leading/trailing whitespace
      .customSanitizer(value => sanitizeInput(value))  // Sanitize HTML
      .isString().withMessage('Food name must be a string')
      .notEmpty().withMessage('Food name is required')
      .isLength({ max: 50 }).withMessage('Food name can be at most 50 characters long'),

    // Sanitize and validate calories: number, positive, max 6 digits
    body('Calorie')
      .trim()
      .isFloat({ min: 0 }).withMessage('Calories must be a positive number')
      .custom(value => {
        if (value.toString().length > 6) {
          throw new Error('Calories value can have at most 6 digits');
        }
        return true;
      }),

    // Sanitize and validate protein: number, positive, max 6 digits
    body('Protein')
      .trim()
      .isFloat({ min: 0 }).withMessage('Protein must be a positive number')
      .custom(value => {
        if (value.toString().length > 6) {
          throw new Error('Protein value can have at most 6 digits');
        }
        return true;
      }),

    // Sanitize and validate carbs: number, positive, max 6 digits
    body('Carbohydrate')
      .trim()
      .isFloat({ min: 0 }).withMessage('Carbs must be a positive number')
      .custom(value => {
        if (value.toString().length > 6) {
          throw new Error('Carbs value can have at most 6 digits');
        }
        return true;
      }),

    // Sanitize and validate fat: number, positive, max 6 digits
    body('Fat')
      .trim()
      .isFloat({ min: 0 }).withMessage('Fat must be a positive number')
      .custom(value => {
        if (value.toString().length > 6) {
          throw new Error('Fat value can have at most 6 digits');
        }
        return true;
      }),

    // Sanitize and validate fiber (optional): number, positive, max 6 digits
    body('Fiber')
      .trim()
      .isFloat({ min: 0 }).withMessage('Fiber must be a positive number')
      .custom(value => {
        if (value.toString().length > 6) {
          throw new Error('Fiber value can have at most 6 digits');
        }
        return true;
      })
  ],
  async (req, res) => {
    console.log("POST request received to create a new food item");
    console.log("Request body:", req.body);

    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const createFood = req.body;
    createFood.userId = req.userId;

    try {
      console.log("Creating a new food item with the following data:", createFood);
      const data = await userFoodModel.create(createFood);
      console.log("Food item created successfully");
      res.status(201).send({ message: "Food created successfully" });
    } catch (err) {
      console.log("Error creating food item:", err);
      res.status(500).send({ message: "Some problem in creating the food" });
    }
  }
);

  ///////////////////////////////////// ADD and UPDATE FOOD /////////////////////////////////////
  
// end point to add a food to a meal and update a food in a meal

// end point to add a food to a meal

app.post("/track", verifyToken, async (req, res) => {
  let trackData = req.body;
  console.log("track data:", trackData);

  const { foodId, quantity, mealNumber, createdAt, eatenDate } = req.body;

  try {
    const newTracking = {
      userId: req.userId,
      details: trackData.details,
      foodId,
      quantity,
      mealNumber,
      createdAt: new Date(),
      eatenDate
    };

    const createdTracking = await trackingModel.create(newTracking);
    return res.status(201).json({ message: "Tracking document created successfully", trackingData: createdTracking });
  } catch (err) {
    console.error("Error logging food:", err);
    return res.status(500).json({ message: "Some problem in logging the food" });
  }
});

// Endpoint to update a specific food entry

app.put("/track/:id", verifyToken, async (req, res) => {
  const { id } = req.params;
  const { foodId, quantity, mealNumber, details } = req.body;

  try {
    const existingTracking = await trackingModel.findOne({
      userId: req.userId,
      _id: id,
    });

    if (existingTracking) {
      // existingTracking.foodId = foodId; -- I got "trackings validation failed" error when I tried to update foodId. Therefore, I removed it.
      existingTracking.quantity = quantity;
      existingTracking.mealNumber = mealNumber;
      existingTracking.details = details;

      await existingTracking.save();

      return res.status(200).json({
        message: "Tracking document updated successfully",
        trackingData: existingTracking,
      });
    } else {
      return res.status(404).json({ message: "Tracking document not found" });
    }
  } catch (err) {
    console.error("Error updating food tracking:", err);
    return res.status(500).json({ message: "Some problem in updating the food tracking" });
  }
});

///////////////////////////////////// MEAL FUNCTIONS /////////////////////////////////////

// end point to fetch the meal foods in the meal function page

app.get('/track/:userId/:mealNumber/:eatenDate', verifyToken, async (req, res) => {
    try {
        // Extract parameters from the request
        const { userId, mealNumber, eatenDate } = req.params;
        console.log('User ID:', userId);
        console.log('Meal number:', mealNumber);
        console.log('Eaten date:', eatenDate);

        let convertedEatenDate;
            try {
                const dateParts = eatenDate.split("-");  // Split by "-"
                convertedEatenDate = `${dateParts[1]}/${dateParts[2]}/${dateParts[0]}`;  // Reassemble in mm/dd/yyyy format
                // Reorder the date parts to mm/dd/yyyy format
                convertedEatenDate = convertedEatenDate.split("/").map(part => parseInt(part)).join("/");
                console.log('Converted Eaten Date:', convertedEatenDate);  // Log the converted date
            } catch (error) {
                convertedEatenDate = eatenDate;  // Use the raw value if parsing fails
            }

        // Assuming trackingModel is your Mongoose model for tracking
        // Fetch food items based on the user ID, meal number, and converted eaten date
        const foods = await trackingModel.find({ userId, mealNumber, eatenDate: convertedEatenDate });
        console.log('Fetched food items:', foods);

        // Send the fetched food items as a JSON response
        res.status(200).json(foods);
    } catch (error) {
        // If an error occurs, send an error response
        console.error('Error fetching food items:', error);
        res.status(500).json({ message: 'Failed to fetch food items' });
    }
});

// end point to delete the meal foods in the meal function page

app.delete("/deleteFoods", verifyToken, async (req, res) => {
    const { foods } = req.body; // Extracting the list of food IDs from the request body
    console.log("Deleting selected foods:", foods);
  
    try {
      // Deleting multiple food entries from the database based on their IDs
      const deleteResult = await trackingModel.deleteMany({ _id: { $in: foods } });
      console.log("Deleted foods:", deleteResult.deletedCount);
  
      // Send a success response
      res.send({ message: `${deleteResult.deletedCount} food(s) deleted successfully` });
    } catch (error) {
      console.error("Error deleting selected foods:", error);
      res.status(500).send({ message: "An error occurred while deleting the selected foods" });
    }
});


app.post("/track/copy", verifyToken, async (req, res) => {
    const { copiedItems, userId, foodId, eatenDate } = req.body;

    console.log("Received copied items:", copiedItems);
    console.log("Received userId:", userId);
    console.log("Received foodId:", foodId);
    console.log("Received eatenDate:", eatenDate);

    try {
        // Iterate through copiedItems to handle each copied item
        for (const copiedItem of copiedItems) {
            const { details, quantity, mealNumber } = copiedItem;
            let foodId;
            if (copiedItem.details && copiedItem.details.foodId) {
                foodId = copiedItem.details.foodId; // Extract foodId from details if available
            } else if (copiedItem.foodId) {
                foodId = copiedItem.foodId; // Extract foodId directly if available
            } else {
                console.log("No foodId found for copiedItem:", copiedItem);
                continue; // Skip processing this copiedItem if no foodId is available
            }
    
            // Parse and format the eatenDate
            const eatenDate = new Date(copiedItem.eatenDate);
            const formattedEatenDate = eatenDate.toISOString().split('T')[0];

            let convertedEatenDate;
            try {
                const dateParts = formattedEatenDate.split("-");  // Split by "-"
                convertedEatenDate = `${dateParts[1]}/${dateParts[2]}/${dateParts[0]}`;  // Reassemble in mm/dd/yyyy format
                // Reorder the date parts to mm/dd/yyyy format
                convertedEatenDate = convertedEatenDate.split("/").map(part => parseInt(part)).join("/");
                console.log('Converted Eaten Date:', convertedEatenDate);  // Log the converted date
            } catch (error) {
                convertedEatenDate = formattedEatenDate;  // Use the raw value if parsing fails
            }
    
            const newTracking = {
                userId,
                foodId: foodId,
                details: {
                    Name: details.Name,
                    Calorie: details.Calorie,
                    Protein: details.Protein,
                    Carbohydrate: details.Carbohydrate,
                    Fat: details.Fat,
                    Fiber: details.Fiber,
                },
                quantity,
                mealNumber,
                eatenDate: convertedEatenDate,
                _id: new mongoose.Types.ObjectId(), // Generate a new ObjectId for the new tracking document
            };
    

            console.log("Creating new tracking document:", newTracking);

            // Save the new tracking document to the database
            await trackingModel.create(newTracking);
            console.log("Tracking document created successfully");
        }

        res.status(201).json({ message: "All tracking documents created successfully" });
    } catch (err) {
        console.error("Error logging food:", err);
        res.status(500).json({ message: "Some problem in logging the food" });
    }
});

///////////////////////////////////// WEIGHT ENTRY /////////////////////////////////////

// Endpoint to add weight entry

app.post("/weights", verifyToken, async (req, res) => {
    const { weight, date, choice } = req.body;
    const userId = req.userId;

    try {
        // Check if a weight entry already exists for the provided date
        const existingEntry = await weightModel.findOne({ userId, date });

        if (existingEntry) {
            // If an entry exists, update it
            existingEntry.weight = weight; // Update the weight value
            existingEntry.choice = choice; // Update the choice value
            await existingEntry.save(); // Save the changes
            res.status(200).json({ message: "Weight entry updated successfully", data: existingEntry });
        } else {
            // If no entry exists, create a new one
            const newWeightEntry = await weightModel.create({ userId, weight, date, choice });
            res.status(201).json({ message: "Weight entry added successfully", data: newWeightEntry });
        }
    } catch (error) {
        console.error("Error adding/updating weight entry:", error);
        res.status(500).json({ message: "Error adding/updating weight entry" });
    }
});




app.get("/weights/:userId/:date", verifyToken, async (req, res) => {
    const userId = req.params.userId;
    const date = new Date(req.params.date);

    try {
        // console.log("Fetching weight data for user:", userId, "on date:", date);

        const userWeight = await weightModel.findOne({
            userId,
            date: { $gte: date, $lt: new Date(date.getTime() + 24 * 60 * 60 * 1000) }, // Filter by date
            choice: req.query.choice // Filter by choice (optional query parameter)
        });

        // console.log("Found weight entry:", userWeight);

        if (!userWeight) {
            // console.log("No weight entry found for user:", userId, "on date:", date);
            return res.status(200).json({});
        }

        res.status(200).json(userWeight);
    } catch (error) {
        // console.error("Error fetching weight data:", error);
        res.status(500).json({ message: "Error fetching weight data" });
    }
});


// Endpoint to fetch weight data for a user within a specific month

app.get("/weights/:userId/:year/:month", verifyToken, async (req, res) => {
    const userId = req.params.userId;
    const year = parseInt(req.params.year);
    const month = parseInt(req.params.month) - 1; // Months are zero-indexed in JavaScript Date object

    try {
        console.log("Fetching weight data for user:", userId, "in year:", year, "and month:", month);

        const startDate = new Date(year, month, 1);
        const endDate = new Date(year, month + 1, 1);

        console.log("Start date:", startDate);
        console.log("End date:", endDate);

        const userWeights = await weightModel.find({
            userId,
            date: { $gte: startDate, $lt: endDate },
        });

        console.log("Found weight entries:", userWeights);

        res.status(200).json(userWeights);
    } catch (error) {
        console.error("Error fetching weight data:", error);
        res.status(500).json({ message: "Error fetching weight data" });
    }
});




// Endpoint to delete a weight entry

// Endpoint to delete a specific weight entry
app.delete("/weights/:id", verifyToken, async (req, res) => {
    const id = req.params.id; // Using the route parameter 'id' to represent the unique identifier (_id)
    console.log("Deleting weight entry with id:", id);
  
    try {
      // Check if the weight entry exists
      const weightEntry = await weightModel.findById(id);
  
      if (!weightEntry) {
        console.log("Weight entry not found");
        return res.status(404).send({ message: "Weight entry not found" });
      }
  
      console.log("Deleting weight entry from database");
      await weightModel.deleteOne({ _id: id }); // Deleting the weight entry based on its _id
      console.log("Weight entry deleted");
  
      // Send a success response
      res.send({ message: "Weight entry deleted successfully" });
    } catch (error) {
      console.error("Error deleting weight entry:", error);
      res.status(500).send({ message: "An error occurred while deleting the weight entry" });
    }
});

// Endpoint to update the selected start date for a user

app.put("/users/:userId/:startDate", verifyToken, async (req, res) => {
    const userId = req.params.userId;
    const { startDate } = req.body;

    try {
        // Update the user's document in the database to store the selected start date
        await userModel.updateOne({ _id: userId }, { startDate });
        res.status(200).json({ message: "Start date updated successfully" });
    } catch (error) {
        console.error("Error updating start date:", error);
        res.status(500).json({ message: "Error updating start date" });
    }
});

// Endpoint to fetch the selected start date for a user
app.get("/users/:userId/:startDate", verifyToken, async (req, res) => {
    const userId = req.params.userId;

    try {
        // Fetch the user's document from the database
        const user = await userModel.findById(userId);

        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        const startDate = user.startDate;
        res.status(200).json({ startDate });
    } catch (error) {
        console.error("Error fetching start date:", error);
        res.status(500).json({ message: "Error fetching start date" });
    }
});

// Endpoint to delete the start date for a user
app.delete("/users/:userId/startdate", verifyToken, async (req, res) => {
    const userId = req.params.userId;

    try {
        // Find the user and set the start date to null or an empty string
        const user = await userModel.findByIdAndUpdate(userId, { startDate: "" }, { new: true });
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        res.status(200).json({ message: "Start date deleted successfully", user });
    } catch (error) {
        console.error("Error deleting start date:", error);
        res.status(500).json({ message: "Error deleting start date" });
    }
});

// Endpoint to change the username

app.post('/update-username', async (req, res) => {
    const { id, newName } = req.body;

    if (!id || !newName) {
        return res.status(400).json({ success: false, message: 'ID ve yeni kullanıcı adı gereklidir.' });
    }

    const isValidUsername = /^[a-z0-9_.]+$/.test(newName);
    if (!isValidUsername || newName.includes(' ')) {
        return res.status(400).json({ success: false, message: 'Küçük harfler ve tek kelimeden oluşmalıdır.' });
    }

    try {
        const existingUser = await userModel.findOne({ name: newName });
        if (existingUser) {
            return res.status(400).json({ success: false, message: 'Kullanıcı adı zaten mevcut.' });
        }

        const user = await userModel.findById(id);
        if (!user) {
            return res.status(404).json({ success: false, message: 'Kullanıcı bulunamadı.' });
        }

        user.name = newName;
        await user.save();

        res.status(200).json({ success: true, message: 'Kullanıcı adı başarıyla güncellendi', user });
    } catch (error) {
        console.error('Error updating username:', error);
        res.status(500).json({ success: false, message: 'Kullanıcı adı güncellenirken bir hata oluştu.' });
    }
});

if (process.env.NODE_ENV === "production") {
  // Serve the static files from the Vite build directory
  app.use(express.static(path.join(__dirname, '/client/dist')));

  // Serve the JavaScript file
  app.get('/assets/index-CW5KkyhG.js', (req, res) => {
    res.sendFile(path.join(__dirname, '/client/dist/assets/index-CW5KkyhG.js'));
  });

  // Handle all other routes by serving the index.html file
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '/client/dist/index.html'));
  });
} else {
  // In development mode, just return a simple message
  app.get('/', (req, res) => {
    res.send('API running');
  });
}

app.listen(process.env.PORT || PORT, () => {
    console.log('Server is running !!!')
})

