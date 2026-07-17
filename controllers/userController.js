const bcrypt = require('bcryptjs');
const { supabase, supabaseAdmin } = require('../supabaseClient');
const { canManage } = require('../utils/roleValidator');
const express = require('express');
const multer = require('multer');
const path = require('path');
const sharp = require('sharp');

// Create a user
const createUser = async (req, res) => {
    const { name, full_name, password, role, center_id } = req.body;  // ✅ added full_name, center_id
    const currentUserRole = req.user.role;

    // Role validation
    if (!canManage(currentUserRole, role)) {
        return res.status(403).send('You are not authorized to create this role');
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    const userPayload = {
        name,                          // username
        full_name,                     // ✅ store full name
        password: hashedPassword,
        role,
        status: (role === "cardadmin" || role === "resource_manager" || role === "franchise_master") ? true : false
    };

    if (center_id) {
        userPayload.center_id = center_id;
    }

    // Insert into Supabase
    const { data, error } = await supabase.from('users').insert([userPayload]);

    if (error) {
        console.error('Error creating user in Supabase:', error.message);
        return res.status(500).json({ error: 'Error creating user' });
    }

    res.status(201).json({ message: 'User created successfully', data });
};


// Edit a user
const editUser = async (req, res) => {
    const { id } = req.params;
    const { name, full_name, password, status } = req.body;  // ✅ added status
    const currentUserRole = req.user.role;

    // Fetch the user to be edited
    const { data: userData, error: fetchError } = await supabase
        .from('users')
        .select('*')
        .eq('id', id)
        .single();

    if (fetchError || !userData) {
        return res.status(404).send('User not found');
    }

    // Role validation - check if current user can manage the target user's role
    if (!canManage(currentUserRole, userData.role)) {
        return res.status(403).send('You are not authorized to edit this user');
    }

    // Prepare update data
    const updateData = {};
    if (name) updateData.name = name;                        // username
    if (full_name) updateData.full_name = full_name;        // ✅ update full name
    if (password) {
        updateData.password = await bcrypt.hash(password, 10);
    }
    // ✅ Allow admin to toggle active/inactive status
    if (typeof status === 'boolean' && currentUserRole === 'admin') {
        updateData.status = status;
    }

    // Update user
    const { data, error } = await supabase
        .from('users')
        .update(updateData)
        .eq('id', id);

    if (error) {
        return res.status(500).json({ error: 'Error updating user' });
    }

    res.status(200).json({ message: 'User updated successfully' });
};

// Delete a user (Admin only)
const deleteUser = async (req, res) => {
    const { id } = req.params;
    const currentUserRole = req.user.role;

    try {
        // Only admin can delete users
        if (currentUserRole !== 'admin') {
            return res.status(403).json({ error: 'Only admin users can delete other users' });
        }

        // Prevent admin from deleting themselves
        if (req.user.id === id) {
            return res.status(400).json({ error: 'You cannot delete your own account' });
        }

        // Check if user exists
        const { data: userData, error: fetchError } = await supabase
            .from('users')
            .select('*')
            .eq('id', id)
            .single();

        if (fetchError || !userData) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Check for foreign key references before deletion
        const references = await checkUserReferences(id);
        if (references.length > 0) {
            return res.status(400).json({ 
                error: `Cannot delete user. User is referenced in: ${references.join(', ')}. Please remove these references first.` 
            });
        }

        // Delete the user
        const { error: deleteError } = await supabase
            .from('users')
            .delete()
            .eq('id', id);

        if (deleteError) {
            console.error('Delete error:', deleteError);
            return res.status(500).json({ error: 'Error deleting user' });
        }

        res.status(200).json({ message: 'User deleted successfully' });
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};

// Helper function to check for foreign key references
const checkUserReferences = async (userId) => {
    const references = [];
    
    try {
        // Check centers table (center_admin)
        const { data: centerData } = await supabase
            .from('centers')
            .select('center_id, center_name')
            .eq('center_admin', userId)
            .limit(1);
        if (centerData && centerData.length > 0) {
            references.push(`Center Admin (${centerData[0].center_name})`);
        }

        // Check states table (state_admin)
        const { data: stateData } = await supabase
            .from('states')
            .select('state_id, state_name')
            .eq('state_admin', userId)
            .limit(1);
        if (stateData && stateData.length > 0) {
            references.push(`State Admin (${stateData[0].state_name})`);
        }

        // Check manager table
        const { data: managerData } = await supabase
            .from('manager')
            .select('user_id')
            .eq('user_id', userId)
            .limit(1);
        if (managerData && managerData.length > 0) {
            references.push('Manager');
        }

        // Check academic_coordinator table
        const { data: academicData } = await supabase
            .from('academic_coordinator')
            .select('user_id')
            .eq('user_id', userId)
            .limit(1);
        if (academicData && academicData.length > 0) {
            references.push('Academic Coordinator');
        }

        // Check financial_partner table
        const { data: financialData } = await supabase
            .from('financial_partner')
            .select('user_id')
            .eq('user_id', userId)
            .limit(1);
        if (financialData && financialData.length > 0) {
            references.push('Financial Partner');
        }

        // Check teachers table
        const { data: teacherData } = await supabase
            .from('teachers')
            .select('teacher')
            .eq('teacher', userId)
            .limit(1);
        if (teacherData && teacherData.length > 0) {
            references.push('Teacher');
        }

        // Check students table (if user is a student)
        const { data: studentData } = await supabase
            .from('students')
            .select('student_id')
            .eq('student_id', userId)
            .limit(1);
        if (studentData && studentData.length > 0) {
            references.push('Student');
        }

    } catch (error) {
        console.error('Error checking user references:', error);
    }

    return references;
};


// Helper function to remove user references before deletion
const removeUserReferences = async (userId) => {
    try {
        // Remove from centers table
        await supabase
            .from('centers')
            .update({ center_admin: null })
            .eq('center_admin', userId);

        // Remove from states table
        await supabase
            .from('states')
            .update({ state_admin: null })
            .eq('state_admin', userId);

        // Remove from manager table
        await supabase
            .from('manager')
            .delete()
            .eq('user_id', userId);

        // Remove from academic_coordinator table
        await supabase
            .from('academic_coordinator')
            .delete()
            .eq('user_id', userId);

        // Remove from financial_partner table
        await supabase
            .from('financial_partner')
            .delete()
            .eq('user_id', userId);

        // Remove from teachers table
        await supabase
            .from('teachers')
            .delete()
            .eq('teacher', userId);

        return { success: true, message: 'User references removed successfully' };
    } catch (error) {
        console.error('Error removing user references:', error);
        return { success: false, error: error.message };
    }
};

// Force delete user (removes references first)
const forceDeleteUser = async (req, res) => {
    const { id } = req.params;
    const currentUserRole = req.user.role;

    try {
        // Only admin can force delete users
        if (currentUserRole !== 'admin') {
            return res.status(403).json({ error: 'Only admin users can force delete other users' });
        }

        // Prevent admin from deleting themselves
        if (req.user.id === id) {
            return res.status(400).json({ error: 'You cannot delete your own account' });
        }

        // Check if user exists
        const { data: userData, error: fetchError } = await supabase
            .from('users')
            .select('*')
            .eq('id', id)
            .single();

        if (fetchError || !userData) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Remove all user references first
        const removeResult = await removeUserReferences(id);
        if (!removeResult.success) {
            return res.status(500).json({ error: `Failed to remove user references: ${removeResult.error}` });
        }

        // Now delete the user
        const { error: deleteError } = await supabase
            .from('users')
            .delete()
            .eq('id', id);

        if (deleteError) {
            console.error('Delete error:', deleteError);
            return res.status(500).json({ error: 'Error deleting user' });
        }

        res.status(200).json({ 
            message: 'User and all references deleted successfully',
            removedReferences: true
        });
    } catch (error) {
        console.error('Force delete user error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};

// Change password (for logged-in user to change their own password)
const changePassword = async (req, res) => {
    try {
        const { current_password, new_password } = req.body;
        const userId = req.user.id; // Get user ID from JWT token

        // Validate input
        if (!current_password || !new_password) {
            return res.status(400).json({ error: 'Current password and new password are required' });
        }

        // Validate new password length (minimum 6 characters)
        if (new_password.length < 6) {
            return res.status(400).json({ error: 'New password must be at least 6 characters long' });
        }

        // Fetch user from database
        const { data: userData, error: fetchError } = await supabase
            .from('users')
            .select('*')
            .eq('id', userId)
            .single();

        if (fetchError || !userData) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Verify current password
        const isPasswordCorrect = await bcrypt.compare(current_password, userData.password);
        if (!isPasswordCorrect) {
            return res.status(401).json({ error: 'Current password is incorrect' });
        }

        // Check if new password is same as current password
        const isSamePassword = await bcrypt.compare(new_password, userData.password);
        if (isSamePassword) {
            return res.status(400).json({ error: 'New password must be different from current password' });
        }

        // Hash new password
        const hashedPassword = await bcrypt.hash(new_password, 10);

        // Update password in database
        const { error: updateError } = await supabase
            .from('users')
            .update({ password: hashedPassword })
            .eq('id', userId);

        if (updateError) {
            console.error('Error updating password:', updateError);
            return res.status(500).json({ error: 'Error updating password' });
        }

        res.status(200).json({ message: 'Password changed successfully' });
    } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};

// Get current user profile (for logged-in user to get their own profile)
const getCurrentUserProfile = async (req, res) => {
    try {
        const userId = req.user.id; // Get user ID from JWT token

        // Fetch user from database
        const { data: userData, error: fetchError } = await supabase
            .from('users')
            .select('id, name, full_name, profile_picture, signature, role')
            .eq('id', userId)
            .single();

        if (fetchError || !userData) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.status(200).json({
            success: true,
            data: userData
        });
    } catch (error) {
        console.error('Get current user profile error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};

// Update current user profile (for logged-in user to update their own profile)
const updateProfile = async (req, res) => {
    try {
        const { full_name } = req.body;
        const userId = req.user.id; // Get user ID from JWT token

        // Validate input
        if (!full_name || full_name.trim() === '') {
            return res.status(400).json({ error: 'Full name is required' });
        }

        // Update user profile in database
        const { error: updateError } = await supabase
            .from('users')
            .update({ full_name: full_name.trim() })
            .eq('id', userId);

        if (updateError) {
            console.error('Error updating profile:', updateError);
            return res.status(500).json({ error: 'Error updating profile' });
        }

        res.status(200).json({
            success: true,
            message: 'Profile updated successfully'
        });
    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};

// Upload profile picture (for logged-in user to upload their own profile picture)
const uploadProfilePicture = async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const userId = req.user.id; // Get user ID from JWT token
        const fileBuffer = req.file.buffer;
        const fileExt = path.extname(req.file.originalname);
        const fileName = `${Date.now()}${fileExt}`;
        const filePath = `${userId}/${fileName}`;

        // Upload to Supabase storage (bucket: user-profiles)
        const { data: uploadData, error: uploadError } = await supabaseAdmin.storage
            .from('user-profiles')
            .upload(filePath, fileBuffer, { upsert: true });

        if (uploadError) {
            console.error('Storage upload error:', uploadError);
            return res.status(500).json({ error: 'Failed to upload profile picture to storage' });
        }

        // Get public URL
        const { data: urlData, error: urlError } = supabaseAdmin.storage
            .from('user-profiles')
            .getPublicUrl(filePath);

        if (urlError) {
            console.error('Get public URL error:', urlError);
            return res.status(500).json({ error: 'Failed to get profile picture URL' });
        }

        const publicUrl = urlData.publicUrl;

        // Update user's profile_picture in database
        const { error: updateError } = await supabase
            .from('users')
            .update({ profile_picture: publicUrl })
            .eq('id', userId);

        if (updateError) {
            console.error('Database update error:', updateError);
            return res.status(500).json({ error: 'Failed to update profile picture in database' });
        }

        res.status(200).json({ 
            success: true, 
            message: 'Profile picture uploaded successfully',
            data: publicUrl 
        });
    } catch (error) {
        console.error('Upload profile picture error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};

// Upload signature (for logged-in user to upload their own signature)
const uploadSignature = async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        // Validate file type and size
        const allowedMimeTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/bmp', 'image/webp'];
        if (!allowedMimeTypes.includes(req.file.mimetype)) {
            return res.status(400).json({ error: 'Invalid file type. Please upload an image file (JPG, PNG, GIF, BMP, or WebP)' });
        }

        if (req.file.size > 5 * 1024 * 1024) {
            return res.status(400).json({ error: 'File size must be less than 5MB' });
        }

        console.log('File validation passed:', {
            mimetype: req.file.mimetype,
            size: req.file.size,
            originalname: req.file.originalname
        });

        const userId = req.user.id; // Get user ID from JWT token
        
        // Convert image to PNG with transparency using Sharp
        let processedBuffer;
        try {
            // First, get image metadata to determine format
            const metadata = await sharp(req.file.buffer).metadata();
            console.log('Image metadata:', metadata);
            
            // Process based on input format
            if (metadata.format === 'png' && metadata.hasAlpha) {
                // If it's already PNG with transparency, just optimize it
                console.log('Processing PNG with existing transparency...');
                processedBuffer = await sharp(req.file.buffer)
                    .png({ 
                        compressionLevel: 6,
                        force: true
                    })
                    .toBuffer();
            } else {
                // For JPG, PNG without alpha, GIF, or other formats
                console.log('Processing image for background removal...');
                
                try {
                    // Try the advanced background removal first
                    const rawData = await sharp(req.file.buffer)
                        .ensureAlpha() // Add alpha channel
                        .raw()
                        .toBuffer();
                    
                    console.log('Processing raw pixel data, length:', rawData.length);
                    const pixels = new Uint8ClampedArray(rawData);
                    
                    // Convert white/light pixels to transparent
                    let transparentCount = 0;
                    let semiTransparentCount = 0;
                    let lightCount = 0;
                    let darkCount = 0;
                    
                    // First pass: find the dominant background color
                    let bgR = 0, bgG = 0, bgB = 0;
                    let bgSampleCount = 0;
                    
                    for (let i = 0; i < pixels.length; i += 4) {
                        const r = pixels[i];
                        const g = pixels[i + 1];
                        const b = pixels[i + 2];
                        
                        // Sample edges and corners for background color
                        const pixelIndex = i / 4;
                        const x = pixelIndex % metadata.width;
                        const y = Math.floor(pixelIndex / metadata.width);
                        
                        // Sample from edges (likely background)
                        if (x < 20 || x > metadata.width - 20 || y < 20 || y > metadata.height - 20) {
                            bgR += r;
                            bgG += g;
                            bgB += b;
                            bgSampleCount++;
                        }
                    }
                    
                    // Calculate average background color
                    bgR = Math.round(bgR / bgSampleCount);
                    bgG = Math.round(bgG / bgSampleCount);
                    bgB = Math.round(bgB / bgSampleCount);
                    
                    console.log('Detected background color:', { r: bgR, g: bgG, b: bgB });
                    
                    // Second pass: remove pixels close to background color
                    for (let i = 0; i < pixels.length; i += 4) {
                        const r = pixels[i];
                        const g = pixels[i + 1];
                        const b = pixels[i + 2];
                        
                        // Calculate color distance from background
                        const colorDistance = Math.sqrt(
                            Math.pow(r - bgR, 2) + 
                            Math.pow(g - bgG, 2) + 
                            Math.pow(b - bgB, 2)
                        );
                        
                        // If pixel is very close to background color, make it transparent
                        if (colorDistance < 40) {
                            pixels[i + 3] = 0; // Set alpha to 0 (transparent)
                            transparentCount++;
                        }
                        // If pixel is somewhat close to background, make it semi-transparent
                        else if (colorDistance < 60) {
                            pixels[i + 3] = Math.round((60 - colorDistance) * 6.375); // Gradual transparency
                            semiTransparentCount++;
                        }
                        // If pixel is moderately close to background, make it mostly transparent
                        else if (colorDistance < 80) {
                            pixels[i + 3] = 40; // 16% opacity
                            lightCount++;
                        }
                        // If pixel is somewhat different from background, make it semi-transparent
                        else if (colorDistance < 100) {
                            pixels[i + 3] = 80; // 31% opacity
                            lightCount++;
                        }
                        // Keep only pixels that are very different from background (signature ink)
                        else {
                            pixels[i + 3] = 255; // Fully opaque
                            darkCount++;
                        }
                    }
                    
                    console.log('Background removal stats:', {
                        totalPixels: pixels.length / 4,
                        transparent: transparentCount,
                        semiTransparent: semiTransparentCount,
                        light: lightCount,
                        dark: darkCount
                    });
                    
                    // Convert back to PNG
                    processedBuffer = await sharp(pixels, {
                        raw: {
                            width: metadata.width,
                            height: metadata.height,
                            channels: 4
                        }
                    })
                    .png({ 
                        compressionLevel: 6,
                        force: true
                    })
                    .toBuffer();
                    
                    console.log('Advanced background removal completed');
                } catch (advancedError) {
                    console.log('Advanced processing failed, using fallback:', advancedError.message);
                    // Fallback to simple conversion if advanced processing fails
                    processedBuffer = await sharp(req.file.buffer)
                        .png({ 
                            compressionLevel: 6,
                            force: true
                        })
                        .toBuffer();
                }
            }
            
            console.log('Image processing completed successfully');
        } catch (sharpError) {
            console.error('Image conversion error:', sharpError);
            console.error('Error details:', sharpError.stack);
            return res.status(400).json({ 
                error: 'Invalid image format or corrupted file',
                details: sharpError.message 
            });
        }

        const fileName = `signature_${Date.now()}.png`; // Always .png extension
        const filePath = `${userId}/signatures/${fileName}`;

        // Upload to Supabase storage (bucket: user-profiles)
        const { data: uploadData, error: uploadError } = await supabaseAdmin.storage
            .from('user-profiles')
            .upload(filePath, processedBuffer, { 
                upsert: true,
                contentType: 'image/png' // Explicitly set content type
            });

        if (uploadError) {
            console.error('Storage upload error:', uploadError);
            return res.status(500).json({ error: 'Failed to upload signature to storage' });
        }

        // Get public URL
        const { data: urlData, error: urlError } = supabaseAdmin.storage
            .from('user-profiles')
            .getPublicUrl(filePath);

        if (urlError) {
            console.error('Get public URL error:', urlError);
            return res.status(500).json({ error: 'Failed to get signature URL' });
        }

        const publicUrl = urlData.publicUrl;

        // Update user's signature in database
        const { error: updateError } = await supabase
            .from('users')
            .update({ signature: publicUrl })
            .eq('id', userId);

        if (updateError) {
            console.error('Database update error:', updateError);
            return res.status(500).json({ error: 'Failed to update signature in database' });
        }

        res.status(200).json({ 
            success: true, 
            message: 'Signature uploaded and converted to PNG successfully',
            data: publicUrl 
        });
    } catch (error) {
        console.error('Upload signature error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};

module.exports = { createUser, editUser, deleteUser, forceDeleteUser, changePassword, getCurrentUserProfile, updateProfile, uploadProfilePicture, uploadSignature };
