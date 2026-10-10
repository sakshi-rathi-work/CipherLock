import React from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { Toaster } from "react-hot-toast";
import { AuthProvider, useAuth } from "./context/AuthContext";
import Navbar from "./components/Navbar";
import Footer from "./components/Footer";
import ProtectedRoute from "./components/ProtectedRoute";
import Login from "./pages/Login";
import Register from "./pages/Register";
import Dashboard from "./pages/Dashboard";
import NotFound from "./pages/NotFound";
import Directory from "./pages/Directory";
import CertificateView from "./pages/CertificateView";
import AdminPanel from "./pages/admin/AdminPanel";
import SendFile from "./pages/SendFile";
import SentFiles from "./pages/SentFiles";
import ReceivedFiles from "./pages/ReceivedFiles";
import Spinner from "./components/Spinner";

function RootRedirect() {
  const { isAuthenticated, loading } = useAuth();
  if (loading) {
    return (
      <div className="flex-1 flex items-center justify-center min-h-[50vh]">
        <Spinner size="lg" className="border-navy border-t-transparent" />
      </div>
    );
  }
  return <Navigate to={isAuthenticated ? "/dashboard" : "/login"} replace />;
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <div className="min-h-screen flex flex-col text-ink font-sans">
          <Toaster
            position="top-right"
            toastOptions={{
              duration: 4000,
              style: {
                background: "#0b1b2e",
                color: "#ffffff",
                border: "1px solid #2a4560",
                borderRadius: "12px",
                fontSize: "0.875rem",
                boxShadow: "0 12px 30px -10px rgba(7,18,31,0.6)",
              },
              success: { iconTheme: { primary: "#c4f16e", secondary: "#0b1b2e" } },
            }}
          />
          <Navbar />
          <main className="flex-1 flex flex-col">
            <Routes>
              {/* Per P1: Root in SPA redirects to dashboard or login */}
              <Route path="/" element={<RootRedirect />} />
              <Route path="/login" element={<Login />} />
              <Route path="/register" element={<Register />} />
              <Route path="/directory" element={<ProtectedRoute><Directory /></ProtectedRoute>} />
              <Route path="/directory/:userId" element={<ProtectedRoute><CertificateView /></ProtectedRoute>} />
              <Route path="/send" element={<ProtectedRoute><SendFile /></ProtectedRoute>} />
              <Route path="/sent" element={<ProtectedRoute><SentFiles /></ProtectedRoute>} />
              <Route path="/received" element={<ProtectedRoute><ReceivedFiles /></ProtectedRoute>} />
              <Route path="/admin" element={<ProtectedRoute><AdminPanel /></ProtectedRoute>} />
              <Route
                path="/dashboard"
                element={
                  <ProtectedRoute>
                    <Dashboard />
                  </ProtectedRoute>
                }
              />
              <Route path="*" element={<NotFound />} />
            </Routes>
          </main>
          <Footer />
        </div>
      </AuthProvider>
    </BrowserRouter>
  );
}
