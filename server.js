const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const http = require('http');
const socketIo = require('socket.io');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

// 中间件
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// JWT密钥
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// 数据库连接
mongoose.connect('mongodb://localhost:27017/minecraft_forum', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('数据库连接成功');
}).catch(err => {
    console.error('数据库连接失败:', err);
});

// 用户模型
const User = mongoose.model('User', {
    username: { type: String, unique: true, required: true },
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
    purchases: [{
        type: String,  // 购买的商品ID
        purchaseDate: { type: Date, default: Date.now }
    }]
});

// 帖子模型
const Post = mongoose.model('Post', {
    title: String,
    content: String,
    category: String,
    author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    createdAt: { type: Date, default: Date.now },
    views: { type: Number, default: 0 },
    comments: [{
        content: String,
        author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        createdAt: { type: Date, default: Date.now }
    }]
});

// 验证Token中间件
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ message: '未提供认证token' });
    }
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: '无效的token' });
        }
        req.user = user;
        next();
    });
};

// 注册路由
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        
        // 检查用户名是否已存在
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ 
                success: false,
                field: 'username',
                message: '用户名已被使用' 
            });
        }
        
        // 检查邮箱是否已存在
        const existingEmail = await User.findOne({ email });
        if (existingEmail) {
            return res.status(400).json({ 
                success: false,
                field: 'email',
                message: '邮箱已被注册' 
            });
        }
        
        // 加密密码
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // 创建新用户
        const user = new User({
            username,
            email,
            password: hashedPassword
        });
        
        await user.save();
        
        res.status(201).json({ 
            success: true,
            message: '注册成功' 
        });
    } catch (err) {
        res.status(500).json({ 
            success: false,
            message: '注册失败' 
        });
    }
});

// 登录路由
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // 查找用户
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({ 
                success: false,
                message: '用户名或密码错误' 
            });
        }
        
        // 验证密码
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ 
                success: false,
                message: '用户名或密码错误' 
            });
        }
        
        // 生成JWT token
        const token = jwt.sign(
            { id: user._id, username: user.username },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        res.json({ 
            success: true,
            token 
        });
    } catch (err) {
        res.status(500).json({ 
            success: false,
            message: '登录失败' 
        });
    }
});

// 检查商品是否已购买
app.get('/api/check-purchase/:productId', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        const hasPurchased = user.purchases.some(p => p.type === req.params.productId);
        
        res.json({ hasPurchased });
    } catch (err) {
        res.status(500).json({ message: '检查失败' });
    }
});

// 记录购买
app.post('/api/record-purchase', authenticateToken, async (req, res) => {
    try {
        const { productId } = req.body;
        const user = await User.findById(req.user.id);
        
        // 检查是否已购买
        if (user.purchases.some(p => p.type === productId)) {
            return res.status(400).json({ message: '已经购买过此商品' });
        }
        
        // 记录购买
        user.purchases.push({ type: productId });
        await user.save();
        
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ message: '记录购买失败' });
    }
});

// API路由
// 获取所有帖子
app.get('/api/posts', async (req, res) => {
    try {
        const posts = await Post.find()
            .populate('author', 'username')
            .sort({ createdAt: -1 });
        res.json(posts);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// 创建新帖子
app.post('/api/posts', authenticateToken, async (req, res) => {
    const post = new Post({
        title: req.body.title,
        content: req.body.content,
        category: req.body.category,
        author: req.user.id
    });

    try {
        const newPost = await post.save();
        // 通过WebSocket通知所有客户端
        io.emit('newPost', newPost);
        res.status(201).json(newPost);
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});

// 获取单个帖子
app.get('/api/posts/:id', async (req, res) => {
    try {
        const post = await Post.findById(req.params.id)
            .populate('author', 'username')
            .populate('comments.author', 'username');
        if (post) {
            post.views += 1;
            await post.save();
            res.json(post);
        } else {
            res.status(404).json({ message: '帖子不存在' });
        }
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// 添加评论
app.post('/api/posts/:id/comments', authenticateToken, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        if (post) {
            post.comments.push({
                content: req.body.content,
                author: req.user.id
            });
            const updatedPost = await post.save();
            // 通过WebSocket通知所有客户端
            io.emit('newComment', {
                postId: req.params.id,
                comment: post.comments[post.comments.length - 1]
            });
            res.json(updatedPost);
        } else {
            res.status(404).json({ message: '帖子不存在' });
        }
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// WebSocket连接处理
io.on('connection', (socket) => {
    console.log('用户已连接');

    socket.on('disconnect', () => {
        console.log('用户已断开连接');
    });
});

// 启动服务器
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`服务器运行在端口 ${PORT}`);
}); 