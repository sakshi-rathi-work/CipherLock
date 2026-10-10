import React, { useState } from "react";
import { Link, NavLink, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import {
  Menu,
  X,
  LogOut,
  LayoutDashboard,
  Send,
  Inbox,
  UploadCloud,
  Award,
  ShieldCheck,
} from "lucide-react";

const LANDING_URL = "http://127.0.0.1:5000/";

export default function Navbar() {
  const { user, isAuthenticated, logout } = useAuth();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate("/login", { state: { notice: "You have been signed out." } });
  };

  const links = [
    { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
    { to: "/send", label: "Send", icon: UploadCloud },
    { to: "/sent", label: "Sent", icon: Send },
    { to: "/received", label: "Received", icon: Inbox },
    { to: "/directory", label: "Certificates", icon: Award },
    ...(user?.is_admin ? [{ to: "/admin", label: "CA Admin", icon: ShieldCheck }] : []),
  ];

  const desktopLink = ({ isActive }) =>
    `flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
      isActive
        ? "bg-white/10 text-white"
        : "text-slate-300 hover:text-white hover:bg-white/5"
    }`;

  const mobileLink = ({ isActive }) =>
    `flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-sm font-medium ${
      isActive ? "bg-white/10 text-white" : "text-slate-300 hover:bg-white/5 hover:text-white"
    }`;

  const initials = (user?.name || "U")
    .split(" ")
    .map((p) => p[0])
    .slice(0, 2)
    .join("")
    .toUpperCase();

  return (
    <nav className="bg-navy/95 backdrop-blur-md border-b border-white/10 text-white h-[68px] flex items-center sticky top-0 z-50 shadow-nav">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 w-full flex items-center justify-between gap-6">
        {/* Brand */}
        <a
          href={LANDING_URL}
          className="group flex items-center gap-2.5 font-bold text-lg tracking-tight"
        >
          <span
            className="w-8 h-8 rounded-[10px] inline-flex items-center justify-center font-extrabold text-[15px] text-navy shadow-lime transition-transform group-hover:scale-105"
            style={{ background: "linear-gradient(145deg,#d4f98c,#a6d94a)" }}
          >
            C
          </span>
          <span className="text-white">
            CipherLock<span className="text-lime">.</span>
          </span>
        </a>

        {/* Desktop navigation */}
        <div className="hidden lg:flex items-center flex-1 justify-between">
          <div className="flex items-center gap-1 ml-6">
            {isAuthenticated ? (
              links.map(({ to, label, icon: Icon }) => (
                <NavLink key={to} to={to} className={desktopLink}>
                  <Icon className="w-4 h-4 opacity-80" aria-hidden="true" />
                  {label}
                </NavLink>
              ))
            ) : (
              <>
                <a href={LANDING_URL} className="px-3 py-2 rounded-lg text-sm font-medium text-slate-300 hover:text-white hover:bg-white/5">
                  Home
                </a>
                <a href={`${LANDING_URL}#security`} className="px-3 py-2 rounded-lg text-sm font-medium text-slate-300 hover:text-white hover:bg-white/5">
                  Security goals
                </a>
              </>
            )}
          </div>

          <div className="flex items-center gap-3">
            {isAuthenticated ? (
              <>
                <div className="hidden xl:flex items-center gap-2.5 pl-3 pr-1 py-1 rounded-full bg-white/5 border border-white/10">
                  <span className="text-xs text-slate-300 max-w-[140px] truncate">{user?.name}</span>
                  <span className="w-7 h-7 rounded-full bg-lime text-navy text-[11px] font-bold inline-flex items-center justify-center">
                    {initials}
                  </span>
                </div>
                <button
                  onClick={handleLogout}
                  className="flex items-center gap-1.5 text-sm text-slate-300 hover:text-white px-3 py-2 rounded-lg hover:bg-white/5 transition-colors"
                  title="Sign out"
                  aria-label="Sign out"
                >
                  <LogOut className="w-4 h-4" aria-hidden="true" />
                  <span>Sign out</span>
                </button>
              </>
            ) : (
              <>
                <Link to="/login" className="px-3 py-2 rounded-lg text-sm font-medium text-slate-300 hover:text-white hover:bg-white/5">
                  Sign in
                </Link>
                <Link to="/register" className="btn-lime px-4 py-2 rounded-lg text-sm">
                  Create account
                </Link>
              </>
            )}
          </div>
        </div>

        {/* Mobile hamburger */}
        <button
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          className="lg:hidden p-2 rounded-lg text-slate-300 hover:text-white hover:bg-white/10"
          aria-label="Toggle navigation menu"
          aria-expanded={mobileMenuOpen}
        >
          {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
        </button>
      </div>

      {/* Mobile menu */}
      {mobileMenuOpen && (
        <div className="lg:hidden absolute top-[68px] left-0 w-full bg-navy border-b border-white/10 px-4 pt-3 pb-5 shadow-panel animate-fade-in">
          <div className="space-y-1">
            {isAuthenticated ? (
              <>
                <div className="px-3 pb-2 text-xs text-slate-400">Signed in as {user?.name}</div>
                {links.map(({ to, label, icon: Icon }) => (
                  <NavLink key={to} to={to} className={mobileLink} onClick={() => setMobileMenuOpen(false)}>
                    <Icon className="w-4 h-4" aria-hidden="true" />
                    {label}
                  </NavLink>
                ))}
                <div className="pt-2 mt-2 border-t border-white/10">
                  <button
                    onClick={() => {
                      setMobileMenuOpen(false);
                      handleLogout();
                    }}
                    className="w-full flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-sm font-medium text-red-300 hover:bg-white/5"
                  >
                    <LogOut className="w-4 h-4" aria-hidden="true" />
                    Sign out
                  </button>
                </div>
              </>
            ) : (
              <>
                <a href={LANDING_URL} className={mobileLink({ isActive: false })} onClick={() => setMobileMenuOpen(false)}>Home</a>
                <a href={`${LANDING_URL}#security`} className={mobileLink({ isActive: false })} onClick={() => setMobileMenuOpen(false)}>Security goals</a>
                <Link to="/login" className={mobileLink({ isActive: false })} onClick={() => setMobileMenuOpen(false)}>Sign in</Link>
                <Link to="/register" className="btn-lime text-center py-2.5 rounded-lg text-sm mt-2 flex" onClick={() => setMobileMenuOpen(false)}>
                  Create account
                </Link>
              </>
            )}
          </div>
        </div>
      )}
    </nav>
  );
}
