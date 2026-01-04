import React, { useState } from 'react';
import { Outlet, useNavigate, useLocation } from 'react-router-dom';
import {
    Box, CssBaseline, AppBar, Toolbar, Typography, Drawer, List, ListItem,
    ListItemButton, ListItemIcon, ListItemText, IconButton, Divider, Button, Avatar
} from '@mui/material';
import {
    Menu as MenuIcon, Dashboard as DashboardIcon, Router as RouterIcon,
    Hub as HubIcon, Security as SecurityIcon, Logout as LogoutIcon, Settings, Speed, People
} from '@mui/icons-material';
import logo from '../assets/logo.png';

const drawerWidth = 260;

const menuItems = [
    { text: 'Dashboard', icon: <DashboardIcon />, path: '/' },
    { text: 'Traffic Analysis', icon: <Speed />, path: '/traffic' },
    { text: 'Origins', icon: <RouterIcon />, path: '/origins' },
    { text: 'Services', icon: <HubIcon />, path: '/services' },
    { text: 'Policy / Firewall', icon: <SecurityIcon />, path: '/policy' },
    { text: 'User Management', icon: <People />, path: '/users' },
];

export default function Layout() {
    const [mobileOpen, setMobileOpen] = useState(false);
    const navigate = useNavigate();
    const location = useLocation();

    const handleLogout = () => {
        localStorage.removeItem('token');
        navigate('/login');
    };

    const drawer = (
        <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
            {/* Logo Header */}
            <Box sx={{ p: 2, textAlign: 'center', borderBottom: '1px solid #1a1a1a' }}>
                <img src={logo} alt="ArmaGuard" style={{ height: 75, marginBottom: 8, objectFit: 'contain' }} />
                <Typography variant="h6" sx={{ color: '#00e5ff', fontWeight: 'bold', letterSpacing: 1 }}>
                    ArmaGuard
                </Typography>
                <Typography variant="caption" sx={{ color: '#444', fontSize: 10 }}>
                    DDoS Protection Manager
                </Typography>
            </Box>

            {/* Menu Items */}
            <List sx={{ flex: 1, pt: 2 }}>
                {menuItems.map((item) => (
                    <ListItem key={item.text} disablePadding sx={{ px: 1, mb: 0.5 }}>
                        <ListItemButton
                            selected={location.pathname === item.path}
                            onClick={() => navigate(item.path)}
                            sx={{
                                borderRadius: 2,
                                '&.Mui-selected': {
                                    bgcolor: '#00e5ff20',
                                    borderLeft: '3px solid #00e5ff',
                                    '&:hover': { bgcolor: '#00e5ff30' }
                                },
                                '&:hover': { bgcolor: '#ffffff10' }
                            }}
                        >
                            <ListItemIcon sx={{ color: location.pathname === item.path ? '#00e5ff' : '#888', minWidth: 40 }}>
                                {item.icon}
                            </ListItemIcon>
                            <ListItemText
                                primary={item.text}
                                primaryTypographyProps={{
                                    fontSize: 14,
                                    color: location.pathname === item.path ? '#fff' : '#aaa'
                                }}
                            />
                        </ListItemButton>
                    </ListItem>
                ))}
            </List>

            {/* Bottom Section */}
            <Divider sx={{ borderColor: '#333' }} />
            <Box sx={{ p: 2 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                    <Avatar sx={{ width: 32, height: 32, bgcolor: '#00e5ff', mr: 1 }}>A</Avatar>
                    <Box>
                        <Typography variant="body2">admin</Typography>
                        <Typography variant="caption" color="textSecondary">Administrator</Typography>
                    </Box>
                </Box>
                <Button
                    fullWidth
                    variant="outlined"
                    color="error"
                    startIcon={<LogoutIcon />}
                    onClick={handleLogout}
                    size="small"
                >
                    Logout
                </Button>
            </Box>
        </Box>
    );

    return (
        <Box sx={{ display: 'flex', width: '100%' }}>
            <CssBaseline />
            <AppBar
                position="fixed"
                sx={{
                    width: { sm: `calc(100% - ${drawerWidth}px)` },
                    ml: { sm: `${drawerWidth}px` },
                    bgcolor: '#0d0d0d',
                    borderBottom: '1px solid #222',
                    boxShadow: 'none',
                }}
            >
                <Toolbar>
                    <IconButton
                        color="inherit"
                        edge="start"
                        onClick={() => setMobileOpen(!mobileOpen)}
                        sx={{ mr: 2, display: { sm: 'none' } }}
                    >
                        <MenuIcon />
                    </IconButton>
                    <Typography variant="h6" sx={{ flexGrow: 1 }}>
                        {menuItems.find(m => m.path === location.pathname)?.text || 'Dashboard'}
                    </Typography>
                    <Typography variant="body2" sx={{ color: '#666', mr: 2 }}>
                        {new Date().toLocaleDateString('ko-KR', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}
                    </Typography>
                </Toolbar>
            </AppBar>

            <Box component="nav" sx={{ width: { sm: drawerWidth }, flexShrink: { sm: 0 } }}>
                <Drawer
                    variant="temporary"
                    open={mobileOpen}
                    onClose={() => setMobileOpen(false)}
                    ModalProps={{ keepMounted: true }}
                    sx={{
                        display: { xs: 'block', sm: 'none' },
                        '& .MuiDrawer-paper': { boxSizing: 'border-box', width: drawerWidth, bgcolor: '#0a0a0a' },
                    }}
                >
                    {drawer}
                </Drawer>
                <Drawer
                    variant="permanent"
                    sx={{
                        display: { xs: 'none', sm: 'block' },
                        '& .MuiDrawer-paper': { boxSizing: 'border-box', width: drawerWidth, bgcolor: '#0a0a0a', borderRight: '1px solid #222' },
                    }}
                    open
                >
                    {drawer}
                </Drawer>
            </Box>

            <Box
                component="main"
                sx={{
                    flexGrow: 1,
                    p: 3,
                    width: { xs: '100%', sm: `calc(100% - ${drawerWidth}px)` },
                    minHeight: '100vh',
                    minWidth: 0,
                    bgcolor: '#050505',
                    overflowX: 'hidden'
                }}
            >
                <Toolbar />
                <Outlet />
            </Box>
        </Box>
    );
}
