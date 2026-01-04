import React, { useState } from 'react';
import { Box, Button, Typography, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Paper, Chip, IconButton, Tooltip } from '@mui/material';
import { Add as AddIcon, Edit, Delete, PlayArrow, Stop } from '@mui/icons-material';

const mockServices = [
    { id: 1, name: 'Arma Reforger #1', origin: 'Origin-001', game: 'Reforger', ports: { game: 20001, browser: 17777, query: 27016 }, status: 'running' },
    { id: 2, name: 'Arma 3 Main', origin: 'Origin-001', game: 'Arma 3', ports: { game: 2302, browser: 2303, query: 2304 }, status: 'running' },
    { id: 3, name: 'Arma 3 Training', origin: 'Origin-002', game: 'Arma 3', ports: { game: 2312, browser: 2313, query: 2314 }, status: 'stopped' },
];

export default function Services() {
    const [services] = useState(mockServices);

    return (
        <Box sx={{ width: '100%' }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 4 }}>
                <Typography variant="h4" sx={{ fontWeight: 'bold', color: '#00e5ff' }}>
                    🎮 Game Services
                </Typography>
                <Button
                    variant="contained"
                    startIcon={<AddIcon />}
                    sx={{
                        background: 'linear-gradient(45deg, #00e5ff, #00b8d4)',
                        color: '#000',
                        fontWeight: 'bold',
                    }}
                >
                    Add Service
                </Button>
            </Box>

            <TableContainer component={Paper} sx={{ bgcolor: '#1a1a2e', borderRadius: 3 }}>
                <Table>
                    <TableHead>
                        <TableRow sx={{ '& th': { borderBottom: '1px solid #333', color: '#888', fontWeight: 'bold' } }}>
                            <TableCell>Service Name</TableCell>
                            <TableCell>Game</TableCell>
                            <TableCell>Target Origin</TableCell>
                            <TableCell>Ports (Game / Browser / Query)</TableCell>
                            <TableCell>Status</TableCell>
                            <TableCell align="right">Actions</TableCell>
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        {services.map((service) => (
                            <TableRow
                                key={service.id}
                                sx={{
                                    '& td': { borderBottom: '1px solid #222' },
                                    '&:hover': { bgcolor: '#ffffff08' }
                                }}
                            >
                                <TableCell>
                                    <Typography variant="body2" sx={{ fontWeight: 'bold' }}>
                                        {service.name}
                                    </Typography>
                                </TableCell>
                                <TableCell>
                                    <Chip
                                        label={service.game}
                                        size="small"
                                        sx={{
                                            bgcolor: service.game === 'Reforger' ? '#00e5ff20' : '#ffab0020',
                                            color: service.game === 'Reforger' ? '#00e5ff' : '#ffab00'
                                        }}
                                    />
                                </TableCell>
                                <TableCell sx={{ color: '#aaa' }}>{service.origin}</TableCell>
                                <TableCell>
                                    <code style={{ color: '#00e5ff', fontSize: 12 }}>
                                        {service.ports.game} / {service.ports.browser} / {service.ports.query}
                                    </code>
                                </TableCell>
                                <TableCell>
                                    <Chip
                                        label={service.status === 'running' ? 'Running' : 'Stopped'}
                                        size="small"
                                        sx={{
                                            bgcolor: service.status === 'running' ? '#00c85320' : '#f5005720',
                                            color: service.status === 'running' ? '#00c853' : '#f50057'
                                        }}
                                    />
                                </TableCell>
                                <TableCell align="right">
                                    <Tooltip title={service.status === 'running' ? 'Stop' : 'Start'}>
                                        <IconButton size="small" sx={{ color: service.status === 'running' ? '#f50057' : '#00c853' }}>
                                            {service.status === 'running' ? <Stop /> : <PlayArrow />}
                                        </IconButton>
                                    </Tooltip>
                                    <Tooltip title="Edit">
                                        <IconButton size="small" sx={{ color: '#00e5ff' }}>
                                            <Edit />
                                        </IconButton>
                                    </Tooltip>
                                    <Tooltip title="Delete">
                                        <IconButton size="small" sx={{ color: '#f50057' }}>
                                            <Delete />
                                        </IconButton>
                                    </Tooltip>
                                </TableCell>
                            </TableRow>
                        ))}
                    </TableBody>
                </Table>
            </TableContainer>
        </Box>
    );
}
