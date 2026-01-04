@echo off
echo Starting Backend...
start cmd /k "cd backend && go run main.go"

echo Waiting for backend...
timeout /t 2 /nobreak > nul

echo Starting Frontend...
start cmd /k "cd frontend && npm run dev"

echo Done. Backend at :8080, Frontend at :5173
pause
