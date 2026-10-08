import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { Menu, X, LogOut, LayoutDashboard, User } from "lucide-react";

export default function Navbar() {
  const { user, isAuthenticated, logout } = useAuth();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate("/login", { state: { notice: "You have been signed out." } });
  };

  return (
    <nav className="bg-navy border-b border-[#1b344d] text-white min-h-[72px] flex items-center sticky top-0 z-50 shadow-nav">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 w-full flex items-center justify-between">
        {/* Brand */}
        <div className="flex items-center space-x-3">
          <a
            href="http://127.0.0.1:5000/"
            className="flex items-center space-x-2 font-bold text-xl tracking-tight hover:opacity-90 transition-opacity"
          >
            <span className="w-[29px] h-[29px] bg-lime text-navy rounded-lg inline-flex items-center justify-center font-extrabold text-base shadow-sm">
              C
            </span>
            <span className="text-white">
              CipherLock<span className="text-lime">.</span>
            </span>
          </a>
        </div>

        {/* Desktop Navigation Links */}
        <div className="hidden md:flex items-center space-x-6 text-sm font-medium">
          <a
            href="http://127.0.0.1:5000/"
            className="text-[#ced9df] hover:text-white transition-colors"
          >
            Home
          </a>
          <a
            href="http://127.0.0.1:5000/#security"
            className="text-[#ced9df] hover:text-white transition-colors"
          >
            Security goals
          </a>

          {isAuthenticated ? (
            <div className="flex items-center space-x-4 pl-4 border-l border-[#24425f]">
              <Link
                to="/directory"
                className="text-[#ced9df] hover:text-white transition-colors"
              >
                Certificates
              </Link>
              {user?.is_admin && (
                <Link
                  to="/admin"
                  className="text-[#ced9df] hover:text-white transition-colors"
                >
                  CA Admin
                </Link>
              )}
              <Link
                to="/dashboard"
                className="flex items-center space-x-1.5 text-[#ced9df] hover:text-white transition-colors"
              >
                <LayoutDashboard className="w-4 h-4 text-lime" />
                <span>Dashboard</span>
              </Link>
              <span className="flex items-center space-x-1 text-xs text-[#9dafbc] bg-navy-surface px-2.5 py-1 rounded-full border border-navy-border">
                <User className="w-3 h-3" />
                <span>{user?.name}</span>
              </span>
              <button
                onClick={handleLogout}
                className="flex items-center space-x-1 text-[#aebdca] hover:text-white transition-colors p-1"
                title="Sign out"
                aria-label="Sign out"
              >
                <LogOut className="w-4 h-4" />
                <span className="text-xs">Sign out</span>
              </button>
            </div>
          ) : (
            <div className="flex items-center space-x-4 pl-4 border-l border-[#24425f]">
              <Link
                to="/login"
                className="text-[#ced9df] hover:text-white transition-colors"
              >
                Sign in
              </Link>
              <Link
                to="/register"
                className="btn-lime px-3.5 py-1.5 rounded-md text-sm font-semibold inline-block"
              >
                Register
              </Link>
            </div>
          )}
        </div>

        {/* Mobile Hamburger Button */}
        <div className="flex md:hidden">
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="p-2 rounded-md text-[#aebdca] hover:text-white hover:bg-navy-surface focus:outline-none focus-visible:ring-2 focus-visible:ring-lime"
            aria-label="Toggle navigation menu"
            aria-expanded={mobileMenuOpen}
          >
            {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
          </button>
        </div>
      </div>

      {/* Mobile Menu Dropdown */}
      {mobileMenuOpen && (
        <div className="md:hidden absolute top-[72px] left-0 w-full bg-navy-surface border-b border-[#24425f] px-4 pt-3 pb-5 space-y-3 shadow-panel">
          <a
            href="http://127.0.0.1:5000/"
            className="block text-[#ced9df] hover:text-white py-1"
            onClick={() => setMobileMenuOpen(false)}
          >
            Home
          </a>
          <a
            href="http://127.0.0.1:5000/#security"
            className="block text-[#ced9df] hover:text-white py-1"
            onClick={() => setMobileMenuOpen(false)}
          >
            Security goals
          </a>
          {isAuthenticated ? (
            <>
              <div className="pt-2 border-t border-[#24425f]">
                <div className="text-xs text-[#9dafbc] mb-2">Signed in as {user?.name}</div>
                <Link
                  to="/directory"
                  className="block text-[#ced9df] hover:text-white py-1"
                  onClick={() => setMobileMenuOpen(false)}
                >
                  Certificates
                </Link>
                {user?.is_admin && (
                  <Link
                    to="/admin"
                    className="block text-[#ced9df] hover:text-white py-1"
                    onClick={() => setMobileMenuOpen(false)}
                  >
                    CA Admin
                  </Link>
                )}
                <Link
                  to="/dashboard"
                  className="block text-[#ced9df] hover:text-white py-1"
                  onClick={() => setMobileMenuOpen(false)}
                >
                  Dashboard
                </Link>
                <button
                  onClick={() => {
                    setMobileMenuOpen(false);
                    handleLogout();
                  }}
                  className="w-full text-left text-red-400 hover:text-red-300 py-1 flex items-center space-x-1"
                >
                  <LogOut className="w-4 h-4" />
                  <span>Sign out</span>
                </button>
              </div>
            </>
          ) : (
            <div className="pt-2 border-t border-[#24425f] flex flex-col space-y-2">
              <Link
                to="/login"
                className="block text-[#ced9df] hover:text-white py-1"
                onClick={() => setMobileMenuOpen(false)}
              >
                Sign in
              </Link>
              <Link
                to="/register"
                className="btn-lime text-center py-2 rounded-md font-semibold"
                onClick={() => setMobileMenuOpen(false)}
              >
                Register
              </Link>
            </div>
          )}
        </div>
      )}
    </nav>
  );
}
