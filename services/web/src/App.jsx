import { Navigate, Route, Routes } from "react-router-dom";

function Placeholder({ label }) {
  return (
    <div className="flex min-h-screen items-center justify-center text-slate-400">
      {label}
    </div>
  );
}

function App() {
  return (
    <Routes>
      <Route path="/login" element={<Placeholder label="Login" />} />
      <Route path="/register" element={<Placeholder label="Register" />} />
      <Route path="/" element={<Placeholder label="Dashboard" />} />
      <Route
        path="/monitors/:id"
        element={<Placeholder label="Monitor detail" />}
      />
      <Route
        path="/notifications"
        element={<Placeholder label="Notifications" />}
      />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default App;
