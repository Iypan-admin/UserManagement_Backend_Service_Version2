const bcrypt = require('bcryptjs');
const supabase = require('../supabaseClient');
const { canManage } = require('../utils/roleValidator');

// Create a user
const createUser = async (req, res) => {
    const { name, full_name, password, role } = req.body;  // ✅ added full_name
    const currentUserRole = req.user.role;

    // Role validation
    if (!canManage(currentUserRole, role)) {
        return res.status(403).send('You are not authorized to create this role');
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert into Supabase
    const { data, error } = await supabase.from('users').insert([
        {
            name,                          // username
            full_name,                     // ✅ store full name
            password: hashedPassword,
            role,
            status: (role === "cardadmin" || role === "resource_manager") ? true : false
        },
    ]);

    if (error) return res.status(500).json({ error: 'Error creating user' });

    res.status(201).json({ message: 'User created successfully', data });
};


// Edit a user
const editUser = async (req, res) => {
    const { id } = req.params;
    const { name, full_name, password } = req.body;  // ✅ added full_name
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
    if (name) updateData.name = name;          // username
    if (full_name) updateData.full_name = full_name;  // ✅ update full name
    if (password) {
        updateData.password = await bcrypt.hash(password, 10);
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

module.exports = { createUser, editUser, deleteUser, forceDeleteUser };
