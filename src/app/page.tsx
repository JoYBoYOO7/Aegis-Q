"use client";

import Image from "next/image";
import { Button } from "@/components/ui/button";
import Link from "next/link";
import { useState, useEffect } from "react";
import { 
  Shield, 
  Lock, 
  Key, 
  Eye, 
  Download, 
  ArrowRight, 
  Sparkles,
  Users,
  Zap,
  CheckCircle,
  Star
} from "lucide-react";

export default function Home() {
  const [isVisible, setIsVisible] = useState(false);
  const [activeFeature, setActiveFeature] = useState(0);

  useEffect(() => {
    setIsVisible(true);
    const interval = setInterval(() => {
      setActiveFeature((prev) => (prev + 1) % features.length);
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  const teamMembers = [
    { 
      name: "Vansh Yadav", 
      regNo: "22BBS0008",
      role: "Full Stack Developer",
      avatar: "👨‍💻"
    },
    { 
      name: "Yash Garg", 
      regNo: "22BBS0183",
      role: "Backend Developer", 
      avatar: "👨‍💻"
    },
  ];

  const features = [
    {
      title: "Advanced Encryption",
      description: "Military-grade AES-256 and Post-Quantum Kyber encryption for ultimate security.",
      icon: Shield,
      color: "text-blue-600"
    },
    {
      title: "Multi-Algorithm Support",
      description: "Choose from AES, Post-Quantum, Hash-Based Signatures, and Threshold Cryptography.",
      icon: Lock,
      color: "text-green-600"
    },
    {
      title: "Smart Password Generator",
      description: "Generate strong, random passwords with customizable complexity and length.",
      icon: Key,
      color: "text-purple-600"
    },
    {
      title: "Real-time Strength Checker",
      description: "Instant password strength evaluation with actionable improvement suggestions.",
      icon: Eye,
      color: "text-orange-600"
    },
    {
      title: "Secure Data Export",
      description: "Export passwords in encrypted format for safe backup and storage.",
      icon: Download,
      color: "text-red-600"
    },
    {
      title: "User-Friendly Interface",
      description: "Modern, intuitive design with seamless user experience across devices.",
      icon: Sparkles,
      color: "text-pink-600"
    },
  ];

  const stats = [
    { label: "Encryption Algorithms", value: "4+" },
    { label: "Security Level", value: "Military Grade" },
    { label: "Team Members", value: "2" },
    { label: "Features", value: "6+" },
  ];

  return (
    <main className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-100">
      {/* Hero Section */}
      <section className="relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-r from-blue-600/10 to-purple-600/10"></div>
        <div className="relative flex flex-col items-center justify-center min-h-screen p-8 text-center">
          <div className={`transition-all duration-1000 ${isVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-10'}`}>
            <div className="flex items-center justify-center mb-6">
              <div className="p-3 bg-blue-600 rounded-full mr-4">
                <Shield className="w-8 h-8 text-white" />
              </div>
              <h1 className="text-6xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
                SecureVault
              </h1>
            </div>
            <p className="text-2xl text-gray-600 mb-8 max-w-2xl mx-auto">
              Next-Generation Password Management with 
              <span className="font-semibold text-blue-600"> Post-Quantum Cryptography</span>
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center mb-12">
              <Link href="/login">
                <Button size="lg" className="px-8 py-3 text-lg bg-blue-600 hover:bg-blue-700 transition-all duration-300 transform hover:scale-105">
                  Get Started
                  <ArrowRight className="ml-2 w-5 h-5" />
                </Button>
              </Link>
              <Link href="/register">
                <Button variant="outline" size="lg" className="px-8 py-3 text-lg border-2 hover:bg-blue-50 transition-all duration-300">
                  Create Account
                </Button>
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* Stats Section */}
      <section className="py-16 bg-white/50 backdrop-blur-sm">
        <div className="max-w-6xl mx-auto px-8">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
            {stats.map((stat, index) => (
              <div 
                key={stat.label}
                className={`text-center transition-all duration-500 delay-${index * 100} ${isVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-10'}`}
              >
                <div className="text-3xl font-bold text-blue-600 mb-2">{stat.value}</div>
                <div className="text-gray-600">{stat.label}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-20">
        <div className="max-w-6xl mx-auto px-8">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-bold text-gray-800 mb-4">
              Advanced Security Features
            </h2>
            <p className="text-xl text-gray-600 max-w-3xl mx-auto">
              Experience the future of password security with cutting-edge cryptographic algorithms
            </p>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            {features.map((feature, index) => {
              const IconComponent = feature.icon;
              return (
                <div
                  key={feature.title}
                  className={`group relative p-8 bg-white rounded-2xl shadow-lg hover:shadow-2xl transition-all duration-500 transform hover:-translate-y-2 border border-gray-100 ${
                    activeFeature === index ? 'ring-2 ring-blue-500 ring-opacity-50' : ''
                  }`}
                  onMouseEnter={() => setActiveFeature(index)}
                >
                  <div className="absolute top-4 right-4 opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                    <Star className="w-5 h-5 text-yellow-400 fill-current" />
                  </div>
                  <div className={`p-3 rounded-xl bg-gray-50 w-fit mb-6 group-hover:scale-110 transition-transform duration-300`}>
                    <IconComponent className={`w-8 h-8 ${feature.color}`} />
                  </div>
                  <h3 className="text-xl font-semibold text-gray-800 mb-4 group-hover:text-blue-600 transition-colors duration-300">
                    {feature.title}
                  </h3>
                  <p className="text-gray-600 leading-relaxed">
                    {feature.description}
                  </p>
                  <div className="mt-6 opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                    <CheckCircle className="w-5 h-5 text-green-500" />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* Team Section */}
      <section className="py-20 bg-gradient-to-r from-blue-50 to-purple-50">
        <div className="max-w-4xl mx-auto px-8">
          <div className="text-center mb-16">
            <div className="flex items-center justify-center mb-4">
              <Users className="w-8 h-8 text-blue-600 mr-3" />
              <h2 className="text-4xl font-bold text-gray-800">Meet Our Team</h2>
            </div>
            <p className="text-xl text-gray-600">
              Dedicated developers committed to your digital security
            </p>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            {teamMembers.map((member, index) => (
              <div
                key={member.regNo}
                className={`bg-white p-8 rounded-2xl shadow-lg hover:shadow-xl transition-all duration-500 transform hover:-translate-y-2 border border-gray-100 ${
                  isVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-10'
                }`}
                style={{ transitionDelay: `${index * 200}ms` }}
              >
                <div className="text-center">
                  <div className="text-6xl mb-4">{member.avatar}</div>
                  <h3 className="text-2xl font-semibold text-gray-800 mb-2">{member.name}</h3>
                  <p className="text-blue-600 font-medium mb-2">{member.role}</p>
                  <p className="text-gray-600">{member.regNo}</p>
                  <div className="mt-4 flex justify-center space-x-2">
                    <div className="w-2 h-2 bg-blue-500 rounded-full"></div>
                    <div className="w-2 h-2 bg-purple-500 rounded-full"></div>
                    <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 bg-gradient-to-r from-blue-600 to-purple-600">
        <div className="max-w-4xl mx-auto px-8 text-center">
          <h2 className="text-4xl font-bold text-white mb-6">
            Ready to Secure Your Digital Life?
          </h2>
          <p className="text-xl text-blue-100 mb-8 max-w-2xl mx-auto">
            Join thousands of users who trust SecureVault for their password management needs
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Link href="/register">
              <Button size="lg" className="px-8 py-3 text-lg bg-white text-blue-600 hover:bg-gray-100 transition-all duration-300 transform hover:scale-105">
                <Zap className="mr-2 w-5 h-5" />
                Start Free Trial
              </Button>
            </Link>
            <Link href="/login">
              <Button variant="outline" size="lg" className="px-8 py-3 text-lg border-white text-white hover:bg-white hover:text-blue-600 transition-all duration-300">
                Sign In
              </Button>
            </Link>
          </div>
        </div>
      </section>
    </main>
  );
}