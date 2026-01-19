const express = require('express');
const multer = require('multer');
const { createUser, editUser, deleteUser, forceDeleteUser, changePassword, getCurrentUserProfile, updateProfile, uploadProfilePicture } = require('../controllers/userController');
const verifyToken = require('../middleware/authMiddleware');

const router = express.Router();

// Multer setup for file uploads (memory storage)
const upload = multer({ storage: multer.memoryStorage() });

router.post('/create', verifyToken, createUser);
router.put('/edit/:id', verifyToken, editUser);
router.delete('/delete/:id', verifyToken, deleteUser);
router.delete('/force-delete/:id', verifyToken, forceDeleteUser);
router.post('/change-password', verifyToken, changePassword);
router.get('/profile', verifyToken, getCurrentUserProfile);
router.put('/profile', verifyToken, updateProfile);
router.post('/upload-profile-picture', verifyToken, upload.single('file'), uploadProfilePicture);

module.exports = router;
