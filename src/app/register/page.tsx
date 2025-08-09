"use client";

import { RegisterForm } from "@/components/register-form";
import { useState, useEffect } from "react";
import { Shield, Lock, ArrowLeft, Sparkles } from "lucide-react";
import Link from "next/link";

export default function Page() {
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    setIsVisible(true);
  }, []);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-purple-50 to-pink-100 relative overflow-hidden">
      {/* Background Pattern */}
      <div className="absolute inset-0 bg-gradient-to-r from-purple-600/5 to-pink-600/5"></div>
      <div className="absolute top-0 right-0 w-72 h-72 bg-purple-400/10 rounded-full blur-3xl translate-x-1/2 -translate-y-1/2"></div>
      <div className="absolute bottom-0 left-0 w-72 h-72 bg-pink-400/10 rounded-full blur-3xl -translate-x-1/2 translate-y-1/2"></div>
      
      {/* Navigation */}
      <div className="relative z-10 p-6">
        <Link href="/" className="inline-flex items-center text-purple-600 hover:text-purple-700 transition-colors duration-300">
          <ArrowLeft className="w-4 h-4 mr-2" />
          Back to Home
        </Link>
      </div>

      {/* Main Content */}
      <div className="relative z-10 flex min-h-screen w-full items-center justify-center p-6 md:p-10">
        <div className="w-full max-w-md">
          {/* Header */}
          <div className={`text-center mb-8 transition-all duration-1000 ${isVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-10'}`}>
            <div className="flex items-center justify-center mb-4">
              <div className="p-3 bg-purple-600 rounded-full mr-3">
                <Sparkles className="w-6 h-6 text-white" />
              </div>
              <h1 className="text-3xl font-bold bg-gradient-to-r from-purple-600 to-pink-600 bg-clip-text text-transparent">
                Join SecureVault
              </h1>
            </div>
            <p className="text-gray-600">
              Create your account and start managing passwords securely
            </p>
          </div>

          {/* Form */}
          <div className={`transition-all duration-1000 delay-300 ${isVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-10'}`}>
            <RegisterForm />
          </div>

          {/* Security Badge */}
          <div className={`mt-8 text-center transition-all duration-1000 delay-500 ${isVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-10'}`}>
            <div className="inline-flex items-center px-4 py-2 bg-purple-50 border border-purple-200 rounded-full">
              <Shield className="w-4 h-4 text-purple-600 mr-2" />
              <span className="text-sm text-purple-700 font-medium">
                Post-Quantum Security
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
