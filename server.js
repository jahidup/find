require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const axios = require('axios');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static('public'));

// ========== CONFIGURATION ==========
const ADMIN_CONFIG = {
  USERNAME: process.env.ADMIN_USERNAME || "Shahid_Ansari",
  PASSWORD: process.env.ADMIN_PASSWORD || "Tracker@3739",
  PIN: process.env.ADMIN_PIN || "2744",
  SECURITY_KEY: process.env.ADMIN_SECURITY_KEY || "NULL_PROTOCOL"
};
const JWT_SECRET = process.env.JWT_SECRET || 'null_protocol_super_secret_2025';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/null_protocol';

// ========== MONGOOSE CONNECTION ==========
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('✅ MongoDB connected'))
.catch(err => console.error('❌ MongoDB connection error:', err));

// ========== MONGOOSE SCHEMAS ==========
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  credits: { type: Number, default: 10 },
  isBlocked: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const apiConfigSchema = new mongoose.Schema({
  type: { type: String, unique: true, required: true },
  url: { type: String, required: true },
  description: String,
  enabled: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

const searchLogSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  apiType: String,
  query: String,
  timestamp: { type: Date, default: Date.now },
  response: mongoose.Schema.Types.Mixed
});

const messageSchema = new mongoose.Schema({
  senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  senderUsername: String,
  content: { type: String, required: true },
  isAdmin: { type: Boolean, default: false },
  timestamp: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const ApiConfig = mongoose.model('ApiConfig', apiConfigSchema);
const SearchLog = mongoose.model('SearchLog', searchLogSchema);
const Message = mongoose.model('Message', messageSchema);

// ========== INITIALIZE DEFAULT DATA ==========
async function initDb() {
  // Default APIs if none exist
  const apiCount = await ApiConfig.countDocuments();
  if (apiCount === 0) {
    const defaultApis = [
      { type: 'phone', url: 'https://ayaanmods.site/number.php?key=annonymous&number={query}', description: 'Phone lookup' },
      { type: 'aadhaar', url: 'https://users-xinfo-admin.vercel.app/api?key=7demo&type=aadhar&term={query}', description: 'Aadhaar lookup' },
      { type: 'vehicle', url: 'https://vehicle-info-aco-api.vercel.app/info?vehicle={query}', description: 'Vehicle RC' },
      { type: 'pan', url: 'https://api.example.com/pan?query={query}', description: 'PAN Verification (demo)' }
    ];
    await ApiConfig.insertMany(defaultApis);
    console.log('📡 Default APIs inserted');
  }
  console.log('✅ Database initialized');
}
initDb().catch(console.error);

// ========== MIDDLEWARE ==========
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token' });
  const token = authHeader.split(' ')[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

function verifyAdmin(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token' });
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    req.admin = decoded;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ========== AUTH ROUTES ==========
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user || !bcrypt.compareSync(password, user.password))
      return res.status(401).json({ error: 'Invalid credentials' });
    if (user.isBlocked) return res.status(403).json({ error: 'Account blocked' });

    const token = jwt.sign(
      { id: user._id, username: user.username, role: 'user' },
      JWT_SECRET
    );
    res.json({ token, username: user.username, credits: user.credits, role: 'user' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/login', (req, res) => {
  const { username, password, pin, securityKey } = req.body;
  if (username === ADMIN_CONFIG.USERNAME &&
      password === ADMIN_CONFIG.PASSWORD &&
      pin === ADMIN_CONFIG.PIN &&
      securityKey === ADMIN_CONFIG.SECURITY_KEY) {
    const token = jwt.sign({ username: ADMIN_CONFIG.USERNAME, role: 'admin' }, JWT_SECRET);
    res.json({ success: true, token, role: 'admin' });
  } else {
    res.status(401).json({ error: 'Invalid admin credentials' });
  }
});

// ========== USER ROUTES ==========
app.get('/api/me', verifyToken, async (req, res) => {
  const user = await User.findById(req.user.id).select('credits isBlocked');
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ credits: user.credits, isBlocked: user.isBlocked });
});

app.get('/api/api-types', verifyToken, async (req, res) => {
  const apis = await ApiConfig.find({ enabled: true }).select('type description');
  res.json(apis);
});

app.post('/api/search', verifyToken, async (req, res) => {
  const { apiType, query } = req.body;
  const userId = req.user.id;

  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const user = await User.findById(userId).session(session);
    if (!user || user.isBlocked) throw new Error('Account blocked');
    if (user.credits < 1) throw new Error('Insufficient credits');

    const api = await ApiConfig.findOne({ type: apiType, enabled: true }).session(session);
    if (!api) throw new Error('API not found');

    let apiUrl = api.url.replace('{query}', encodeURIComponent(query));

    // Deduct credit
    user.credits -= 1;
    await user.save({ session });

    let result = {};
    try {
      const response = await axios.get(apiUrl, { timeout: 15000 });
      result = response.data;
    } catch (error) {
      result = { error: 'API failed', message: error.message };
    }
    result.developer = 'Shahid Ansari';
    result.powered_by = 'NULL PROTOCOL';

    // Log search
    await SearchLog.create([{
      userId: user._id,
      apiType,
      query,
      response: result
    }], { session });

    await session.commitTransaction();
    res.json({ success: true, credits_left: user.credits, data: result });
  } catch (err) {
    await session.abortTransaction();
    res.status(400).json({ error: err.message });
  } finally {
    session.endSession();
  }
});

// ========== MESSAGING ROUTES ==========
// Get all messages (for users and admin)
app.get('/api/messages', verifyToken, async (req, res) => {
  try {
    const messages = await Message.find()
      .sort({ timestamp: -1 })
      .limit(100)
      .lean();
    res.json(messages.reverse()); // return oldest first
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Send a message (user or admin)
app.post('/api/messages', verifyToken, async (req, res) => {
  const { content } = req.body;
  if (!content || content.trim() === '') {
    return res.status(400).json({ error: 'Message content required' });
  }
  try {
    const user = await User.findById(req.user.id);
    const isAdmin = req.user.role === 'admin';
    const message = await Message.create({
      senderId: user?._id || null,
      senderUsername: isAdmin ? 'ADMIN' : user.username,
      content: content.trim(),
      isAdmin
    });
    res.json({ success: true, message });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete a message (admin only)
app.delete('/api/messages/:id', verifyAdmin, async (req, res) => {
  try {
    await Message.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========== ADMIN ROUTES ==========
app.get('/admin/stats', verifyAdmin, async (req, res) => {
  const totalUsers = await User.countDocuments();
  const totalCredits = await User.aggregate([{ $group: { _id: null, sum: { $sum: '$credits' } } }]);
  const totalSearches = await SearchLog.countDocuments();
  res.json({
    totalUsers,
    totalCredits: totalCredits[0]?.sum || 0,
    totalSearches
  });
});

app.get('/admin/users', verifyAdmin, async (req, res) => {
  const search = req.query.search || '';
  let filter = {};
  if (search) {
    filter.username = { $regex: search, $options: 'i' };
  }
  const users = await User.find(filter).select('-password').sort({ createdAt: -1 });
  res.json(users);
});

app.post('/admin/user', verifyAdmin, async (req, res) => {
  const { username, password, credits, isBlocked } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  try {
    const hashed = bcrypt.hashSync(password, 10);
    const user = await User.create({
      username,
      password: hashed,
      credits: credits || 10,
      isBlocked: isBlocked || false
    });
    res.json({ success: true, id: user._id });
  } catch (err) {
    res.status(400).json({ error: 'Username already exists' });
  }
});

app.put('/admin/user/:id', verifyAdmin, async (req, res) => {
  const { credits, isBlocked } = req.body;
  await User.findByIdAndUpdate(req.params.id, { credits, isBlocked });
  res.json({ success: true });
});

app.post('/admin/bulk-credits', verifyAdmin, async (req, res) => {
  const { amount } = req.body;
  await User.updateMany({}, { $inc: { credits: amount } });
  res.json({ success: true });
});

app.delete('/admin/user/:id', verifyAdmin, async (req, res) => {
  const result = await User.findByIdAndDelete(req.params.id);
  if (!result) return res.status(404).json({ error: 'User not found' });
  // Also delete related logs
  await SearchLog.deleteMany({ userId: req.params.id });
  res.json({ success: true });
});

app.get('/admin/logs', verifyAdmin, async (req, res) => {
  const { userId } = req.query;
  let filter = {};
  if (userId) filter.userId = userId;
  const logs = await SearchLog.find(filter)
    .populate('userId', 'username')
    .sort({ timestamp: -1 })
    .limit(200)
    .lean();
  res.json(logs);
});

// API Configs
app.get('/admin/api-configs', verifyAdmin, async (req, res) => {
  const configs = await ApiConfig.find().sort({ type: 1 });
  res.json(configs);
});

app.post('/admin/api-configs', verifyAdmin, async (req, res) => {
  const { type, url, description, enabled } = req.body;
  try {
    await ApiConfig.create({ type, url, description, enabled });
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: 'API type already exists' });
  }
});

app.put('/admin/api-configs/:id', verifyAdmin, async (req, res) => {
  const { type, url, description, enabled } = req.body;
  await ApiConfig.findByIdAndUpdate(req.params.id, { type, url, description, enabled });
  res.json({ success: true });
});

app.delete('/admin/api-configs/:id', verifyAdmin, async (req, res) => {
  await ApiConfig.findByIdAndDelete(req.params.id);
  res.json({ success: true });
});

app.post('/admin/test-api', verifyAdmin, async (req, res) => {
  const { url, query } = req.body;
  const testUrl = url.replace('{query}', encodeURIComponent(query || 'test'));
  try {
    const response = await axios.get(testUrl, { timeout: 10000 });
    res.json({ success: true, data: response.data });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

// ========== SERVE FRONTEND ==========
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
