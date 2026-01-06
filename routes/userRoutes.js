const express = require('express');
const { createUser, editUser, deleteUser, forceDeleteUser } = require('../controllers/userController');
const verifyToken = require('../middleware/authMiddleware');

const router = express.Router();

router.post('/create', verifyToken, createUser);
router.put('/edit/:id', verifyToken, editUser);
router.delete('/delete/:id', verifyToken, deleteUser);
router.delete('/force-delete/:id', verifyToken, forceDeleteUser);

module.exports = router;
