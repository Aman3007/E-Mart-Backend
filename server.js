// server.js - Complete Backend API
require("dotenv").config();
const productsData = require("./products.json");


const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();

// Middleware
app.use(cors({
  origin: 'https://e-mart-snowy.vercel.app/',
   methods: ["GET", "POST", "PUT", "DELETE"],
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());



// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Product Schema
const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  title: { type: String, required: true },
  brand: { type: String, required: true },
  category: { type: String, required: true },
  price: { type: Number, required: true },
  rating: { type: Number, required: true },
  description: { type: String, required: true },
  stock: { type: Number, required: true },
  image: { type: String, required: true },
  reviews: [{ 
    user: String, 
    comment: String, 
    rating: Number,
    date: Date 
  }]
});

const Product = mongoose.model('Product', productSchema);


// MongoDB Connection

mongoose
  .connect(process.env.MONGODB_URI)
  .then(async () => {
    console.log("MongoDB connected");

    // AUTO-SEED PRODUCTS
    const productCount = await Product.countDocuments();

    if (productCount === 0) {
      await Product.insertMany(productsData);
      console.log(`Seeded ${productsData.length} products from JSON`);
    } else {
      console.log("Products already exist. Skipping seeding.");
    }
  })
  .catch((err) => console.error("MongoDB connection error:", err));


// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-here';

// Cookie options
const cookieOptions = {
  httpOnly: true,
 sameSite: "none",
  secure: true,
  maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
};

// Auth Middleware
const authMiddleware = (req, res, next) => {
  const token = req.cookies?.token;
  
  if (!token) {
    return res.status(401).json({ message: 'No authentication token provided' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// ===== AUTH ROUTES =====

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Validation
    if (!name || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = new User({
      name,
      email,
      password: hashedPassword
    });

    await user.save();

    // Generate token
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });

    // Set cookie
    res.cookie('token', token, cookieOptions);

    res.status(201).json({
      message: 'User registered successfully',
      user: { id: user._id, name: user.name, email: user.email }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Generate token
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });

    // Set cookie
    res.cookie('token', token, cookieOptions);

    res.json({
      message: 'Login successful',
      user: { id: user._id, name: user.name, email: user.email }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Get current user
app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token', cookieOptions);
  res.json({ message: 'Logged out successfully' });
});

// ===== PRODUCT ROUTES =====

// Get all products with pagination, search, sort, and filters
app.get('/api/products', async (req, res) => {
  try {
    const { 
      page = 1, 
      limit = 8, 
      search = '', 
      sortBy = 'createdAt',
      order = 'desc',
      category,
      brand,
      minPrice,
      maxPrice
    } = req.query;

    // Build query
    const query = {};
    
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { title: { $regex: search, $options: 'i' } },
        { brand: { $regex: search, $options: 'i' } },
        { category: { $regex: search, $options: 'i' } }
      ];
    }

    if (category) query.category = category;
    if (brand) query.brand = brand;
    if (minPrice || maxPrice) {
      query.price = {};
      if (minPrice) query.price.$gte = Number(minPrice);
      if (maxPrice) query.price.$lte = Number(maxPrice);
    }

    // Build sort
    const sortOptions = {};
    sortOptions[sortBy] = order === 'asc' ? 1 : -1;

    // Execute query with pagination
    const skip = (page - 1) * limit;
    const products = await Product.find(query)
      .sort(sortOptions)
      .skip(skip)
      .limit(Number(limit));

    const total = await Product.countDocuments(query);

    res.json({
      products,
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Get latest products (for home page)
app.get('/api/products/latest', async (req, res) => {
  try {
    const limit = req.query.limit || 10;
    const products = await Product.find()
      .sort({ createdAt: -1 })
      .limit(Number(limit));
    
    res.json(products);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Get single product
app.get('/api/products/:id', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    
    if (!product) {
      return res.status(404).json({ message: 'Product not found' });
    }

    res.json(product);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Get unique categories
app.get('/api/categories', async (req, res) => {
  try {
    const categories = await Product.distinct('category');
    res.json(categories);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Get unique brands
app.get('/api/brands', async (req, res) => {
  try {
    const brands = await Product.distinct('brand');
    res.json(brands);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// ===== SEED DATABASE =====
app.post('/api/seed', async (req, res) => {
  try {
    await Product.deleteMany({});
    
    const products = Array.from({ length: 50 }, (_, i) => {
      const categories = ['Fruits', 'Vegetables', 'Dairy', 'Bakery', 'Beverages', 'Snacks', 'Meat', 'Seafood'];
      const brands = ['FreshFarm', 'OrganicPro', 'GreenValley', 'PureHarvest', 'NatureBest', 'FarmFresh'];
      
      const category = categories[i % categories.length];
      const brand = brands[i % brands.length];
      
      return {
        name: `Product ${i + 1}`,
        title: `Premium ${category} Item ${i + 1}`,
        brand,
        category,
        price: Math.floor(Math.random() * 50) + 10,
        rating: (Math.random() * 2 + 3).toFixed(1),
        description: `This is a high-quality ${category.toLowerCase()} product from ${brand}. Fresh, organic, and delivered straight to your door. Perfect for your daily needs and healthy lifestyle.`,
        stock: Math.floor(Math.random() * 100) + 10,
        image: `https://images.unsplash.com/photo-${1500000000000 + i}?w=400&h=400&fit=crop`,
        reviews: [
          {
            user: 'John Doe',
            comment: 'Great product! Highly recommended.',
            rating: 5,
            date: new Date()
          },
          {
            user: 'Jane Smith',
            comment: 'Good quality and fresh delivery.',
            rating: 4,
            date: new Date()
          }
        ]
      };
    });

    await Product.insertMany(products);
    res.json({ message: 'Database seeded successfully', count: products.length });
  } catch (error) {
    res.status(500).json({ message: 'Seed error', error: error.message });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'Server is running' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
