const express = require('express');
const userRoutes = require('./routes/userRoutes');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());

app.use(cors());
app.use('/user', userRoutes);

app.listen(3001, () => {
    console.log('User Management Service running on port 3001');
});
