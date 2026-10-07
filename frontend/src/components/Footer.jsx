import React from "react";

export default function Footer() {
  return (
    <footer className="bg-navy-deep text-[#91a0ad] py-5 text-xs border-t border-[#1b344d] mt-auto">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col md:flex-row justify-between items-center gap-2 text-center md:text-left">
        <span>© 2026 CipherLock · Computer Network Security project</span>
        <span className="text-[#aebdca]">Phase 2 · Authentication and Database Models</span>
      </div>
    </footer>
  );
}
