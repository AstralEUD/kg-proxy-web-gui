import { useState } from 'react';
import {
    Box,
    Typography,
    Paper,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    IconButton,
    Tooltip,
    Chip,
    Button
} from '@mui/material';
import {
    Delete as DeleteIcon,
    Refresh as RefreshIcon,
    Block as BlockIcon,
    Info as InfoIcon
} from '@mui/icons-material';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import client from '../api/client';
import IPInfoModal from '../components/IPInfoModal';

const ActiveBlocks = () => {
    const queryClient = useQueryClient();
    const [selectedIP, setSelectedIP] = useState(null); // For Modal

    const { data: blockedData, isLoading, refetch } = useQuery({
        queryKey: ['activeBlocks'],
        queryFn: async () => {
            const res = await client.get('/traffic/blocked');
            // Backend returns { data: [], count: N }
            return res.data;
        },
        refetchInterval: 5000 // Auto refresh every 5s
    });

    const unblockMutation = useMutation({
        mutationFn: (ip) => client.delete('/traffic/blocked', { data: { ip } }),
        onSuccess: () => {
            queryClient.invalidateQueries(['activeBlocks']);
        }
    });

    const handleUnblock = (ip) => {
        if (window.confirm(`Are you sure you want to unblock ${ip}?`)) {
            unblockMutation.mutate(ip);
        }
    };

    const getReasonColor = (reason) => {
        switch (reason) {
            case 'manual': return 'primary';
            case 'rate_limit': return 'warning';
            case 'geoip': return 'info';
            case 'flood': return 'error';
            default: return 'default';
        }
    };

    return (
        <Box>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
                <Typography variant="h5" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <BlockIcon color="error" /> Active eBPF Blocks
                </Typography>
                <Button startIcon={<RefreshIcon />} onClick={refetch}>Refresh</Button>
            </Box>

            <Paper sx={{ width: '100%', mb: 2 }}>
                <TableContainer>
                    <Table>
                        <TableHead>
                            <TableRow>
                                <TableCell>IP Address</TableCell>
                                <TableCell>Reason</TableCell>
                                <TableCell>Expires In (TTL)</TableCell>
                                <TableCell align="right">Actions</TableCell>
                            </TableRow>
                        </TableHead>
                        <TableBody>
                            {isLoading ? (
                                <TableRow>
                                    <TableCell colSpan={4} align="center">Loading active blocks...</TableCell>
                                </TableRow>
                            ) : blockedData?.data?.length === 0 ? (
                                <TableRow>
                                    <TableCell colSpan={4} align="center">No active blocks currently.</TableCell>
                                </TableRow>
                            ) : (
                                blockedData?.data?.map((row) => (
                                    <TableRow key={row.ip}>
                                        <TableCell>
                                            <Button
                                                variant="text"
                                                startIcon={<InfoIcon fontSize="small" />}
                                                onClick={() => setSelectedIP(row.ip)}
                                                sx={{ textTransform: 'none' }}
                                            >
                                                {row.ip}
                                            </Button>
                                        </TableCell>
                                        <TableCell>
                                            <Chip
                                                label={row.reason}
                                                size="small"
                                                color={getReasonColor(row.reason)}
                                                variant="outlined"
                                            />
                                        </TableCell>
                                        <TableCell>
                                            {row.ttl_seconds > 0 ? `${row.ttl_seconds}s` : 'Permanent'}
                                        </TableCell>
                                        <TableCell align="right">
                                            <Tooltip title="Unblock Now">
                                                <IconButton onClick={() => handleUnblock(row.ip)} color="primary">
                                                    <DeleteIcon />
                                                </IconButton>
                                            </Tooltip>
                                        </TableCell>
                                    </TableRow>
                                ))
                            )}
                        </TableBody>
                    </Table>
                </TableContainer>
            </Paper>

            {/* IP Info Modal */}
            <IPInfoModal
                ip={selectedIP}
                open={Boolean(selectedIP)}
                onClose={() => setSelectedIP(null)}
            />
        </Box>
    );
};

export default ActiveBlocks;
