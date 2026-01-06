const permissions = {
    admin: ['manager', 'financial', 'academic', 'state', 'center', 'teacher', 'cardadmin', 'resource_manager'],
    manager: ['state', 'center'],
    academic: ['teacher'],
};

const canManage = (userRole, targetRole) => {
    // Admin can manage any role
    if (userRole === 'admin') {
        return true;
    }
    return permissions[userRole]?.includes(targetRole);
};

module.exports = { canManage };
