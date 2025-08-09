"use client";

import { LoginForm } from "@/components/login-form";
import { useState, useEffect } from "react";
import { Shield, Lock, ArrowLeft } from "lucide-react";
import Link from "next/link";

export default function Page() {
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    setIsVisible(true);
  }, []);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-100 relative overflow-hidden">
      {/* Background Pattern */}
      <div className="absolute inset-0 bg-gradient-to-r from-blue-600/5 to-purple-600/5"></div>
      <div className="absolute top-0 left-0 w-72 h-72 bg-blue-400/10 rounded-full blur-3xl -translate-x-1/2 -translate-y-1/2"></div>
      <div className="absolute bottom-0 right-0 w-72 h-72 bg-purple-400/10 rounded-full blur-3xl translate-x-1/2 translate-y-1/2"></div>
      
      {/* Navigation */}
      <div className="relative z-10 p-6">
        <Link href="/" className="inline-flex items-center text-blue-600 hover:text-blue-700 transition-colors duration-300">
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
              <div className="p-3 bg-blue-600 rounded-full mr-3">
                <Shield className="w-6 h-6 text-white" />
              </div>
              <h1 className="text-3xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
                Welcome Back
              </h1>
            </div>
            <p className="text-gray-600">
              Access your secure password vault with advanced encryption
            </p>
          </div>

          {/* Form */}
          <div className={`transition-all duration-1000 delay-300 ${isVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-10'}`}>
            <LoginForm />
          </div>

          {/* Security Badge */}
          <div className={`mt-8 text-center transition-all duration-1000 delay-500 ${isVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-10'}`}>
            <div className="inline-flex items-center px-4 py-2 bg-green-50 border border-green-200 rounded-full">
              <Lock className="w-4 h-4 text-green-600 mr-2" />
              <span className="text-sm text-green-700 font-medium">
                Military-Grade Encryption
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
