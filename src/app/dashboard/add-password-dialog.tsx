"use client";

import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select } from "@/components/ui/select";
import { useState } from "react";
import { storePassword } from "@/app/server/password";
import { Wand2, Eye, EyeOff, Shield, Sparkles, Lock, User, Globe, ArrowRight, Zap, Cpu, Layers } from "lucide-react";
import { LoadingSpinner } from "@/components/ui/loading-spinner";
import { revalidatePath } from "next/cache";
import { revalidate } from "../server/revalidate";
import { toast } from "sonner";
import { Card } from "@/components/ui/card";
import { Info } from "lucide-react";

interface AddPasswordDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

const encryptionAlgorithms = [
  {
    value: "aes-256-gcm",
    label: "AES-256-GCM (Standard)",
    description: "Fast, widely used symmetric encryption"
  },
  // {
  //   value: "kyber-768",
  //   label: "Kyber-768 (Post-Quantum)",
  //   description: "Quantum-resistant key encapsulation"
  // },
  // {
  //   value: "aes-256-gcm-hybrid",
  //   label: "AES-256-GCM + Kyber (Hybrid)",
  //   description: "Maximum security with both algorithms"
  // }
];

export default function AddPasswordDialog({
  open,
  onOpenChange,
}: AddPasswordDialogProps) {
  const [service, setService] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [passwordStrength, setPasswordStrength] = useState(0);
  const [showPassword, setShowPassword] = useState(false);
  const [issues, setIssues] = useState<string[]>([]);
  const [cryptoAlgorithm, setCryptoAlgorithm] = useState("aes-256-gcm");
  const [isLoading, setIsLoading] = useState(false);

  const checkPasswordStrength = (pass: string): number => {
    let score = 0;
    let currentIssue = "";

    if (pass.length < 8) {
      currentIssue = "Password must have at least 8 characters";
    } else if (!pass.match(/[A-Z]/)) {
      currentIssue = "Password must include an uppercase letter";
    } else if (!pass.match(/[a-z]/)) {
      currentIssue = "Password must include a lowercase letter";
    } else if (!pass.match(/[0-9]/)) {
      currentIssue = "Password must include a number";
    } else if (!pass.match(/[^A-Za-z0-9]/)) {
      currentIssue = "Password must include a special character";
    }

    if (pass.length >= 8) score += 1;
    if (pass.match(/[A-Z]/)) score += 1;
    if (pass.match(/[a-z]/)) score += 1;
    if (pass.match(/[0-9]/)) score += 1;
    if (pass.match(/[^A-Za-z0-9]/)) score += 1;

    setIssues([currentIssue]);
    return score;
  };

  const getStrengthColor = (strength: number): string => {
    if (strength <= 1) return "bg-red-500";
    if (strength <= 3) return "bg-yellow-500";
    return "bg-green-500";
  };

  const getStrengthText = (strength: number): string => {
    if (strength <= 1) return "Weak";
    if (strength <= 3) return "Medium";
    return "Strong";
  };

  const handlePasswordChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const newPassword = e.target.value;
    setPassword(newPassword);
    setPasswordStrength(checkPasswordStrength(newPassword));
  };

  const getAlgorithmInfo = (algorithm: string) => {
    const algo = encryptionAlgorithms.find(a => a.value === algorithm);
    return algo || encryptionAlgorithms[0];
  };

  const getAlgorithmIcon = (algorithm: string) => {
    switch (algorithm) {
      case "aes-256-gcm":
        return <Shield className="w-4 h-4" />;
      case "kyber-768":
        return <Cpu className="w-4 h-4" />;
      case "aes-256-gcm-hybrid":
        return <Layers className="w-4 h-4" />;
      default:
        return <Shield className="w-4 h-4" />;
    }
  };

  const getAlgorithmColor = (algorithm: string) => {
    switch (algorithm) {
      case "aes-256-gcm":
        return "text-blue-600 bg-blue-50";
      case "kyber-768":
        return "text-purple-600 bg-purple-50";
      case "aes-256-gcm-hybrid":
        return "text-green-600 bg-green-50";
      default:
        return "text-blue-600 bg-blue-50";
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);

    try {
      const storePasswordPromise = storePassword({
        service,
        username,
        password,
        algorithm: cryptoAlgorithm,
      });

      toast.promise(storePasswordPromise, {
        loading: "Securing your password with military-grade encryption...",
        success: "Password securely stored! 🔐",
        error: "Failed to store password",
      });

      await storePasswordPromise;
      revalidate("/dashboard");

      onOpenChange(false);
      setService("");
      setUsername("");
      setPassword("");
      setPasswordStrength(0);
      setCryptoAlgorithm("aes-256-gcm");
    } catch (error) {
      console.error("Failed to store password:", error);
    } finally {
      setIsLoading(false);
    }
  };

  const generatePassword = () => {
    const length = 16;
    const charset =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
    const numbers = "0123456789";

    let generatedPassword = numbers.charAt(
      Math.floor(Math.random() * numbers.length)
    );
    for (let i = 1; i < length; i++) {
      generatedPassword += charset.charAt(
        Math.floor(Math.random() * charset.length)
      );
    }

    generatedPassword = generatedPassword
      .split("")
      .sort(() => Math.random() - 0.5)
      .join("");

    setPassword(generatedPassword);
    setPasswordStrength(checkPasswordStrength(generatedPassword));
    toast.success("Strong password generated! 🔥");
  };

  const selectedAlgorithm = getAlgorithmInfo(cryptoAlgorithm);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[500px] bg-white/95 backdrop-blur-sm border-0 shadow-2xl">
        <DialogHeader className="text-center pb-6">
          <div className="flex items-center justify-center mb-4">
            <div className="p-3 bg-gradient-to-r from-blue-600 to-purple-600 rounded-2xl shadow-lg">
              <Shield className="h-8 w-8 text-white" />
            </div>
          </div>
          <DialogTitle className="text-2xl font-bold text-gray-800">Add New Password</DialogTitle>
          <p className="text-gray-600">Securely store your credentials with advanced encryption</p>
        </DialogHeader>
        
        <form onSubmit={handleSubmit} className="space-y-6">
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="service" className="text-sm font-medium text-gray-700 flex items-center">
                <Globe className="w-4 h-4 mr-2" />
                Service Name
              </Label>
              <Input
                id="service"
                value={service}
                onChange={(e) => setService(e.target.value)}
                placeholder="e.g., Google, Twitter, GitHub"
                required
                className="w-full px-4 py-3 border border-gray-200 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-300 bg-white/50 backdrop-blur-sm text-gray-900 placeholder:text-gray-500"
              />
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="username" className="text-sm font-medium text-gray-700 flex items-center">
                <User className="w-4 h-4 mr-2" />
                Username or Email
              </Label>
              <Input
                id="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter your username or email"
                required
                className="w-full px-4 py-3 border border-gray-200 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-300 bg-white/50 backdrop-blur-sm text-gray-900 placeholder:text-gray-500"
              />
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="password" className="text-sm font-medium text-gray-700 flex items-center">
                <Lock className="w-4 h-4 mr-2" />
                Password
              </Label>
              <div className="flex gap-2">
                <Input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={handlePasswordChange}
                  placeholder="Enter or generate a strong password"
                  required
                  className="flex-1 px-4 py-3 border border-gray-200 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-300 bg-white/50 backdrop-blur-sm text-gray-900 placeholder:text-gray-500"
                />
                <Button
                  type="button"
                  variant="outline"
                  size="icon"
                  onClick={() => setShowPassword(!showPassword)}
                  className="p-3 border border-gray-200 rounded-xl hover:bg-gray-50 transition-colors"
                  title={showPassword ? "Hide Password" : "Show Password"}
                >
                  {showPassword ? (
                    <EyeOff className="h-4 w-4" />
                  ) : (
                    <Eye className="h-4 w-4" />
                  )}
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  size="icon"
                  onClick={generatePassword}
                  className="p-3 border border-gray-200 rounded-xl hover:bg-purple-50 hover:border-purple-300 transition-colors"
                  title="Generate Strong Password"
                >
                  <Wand2 className="h-4 w-4" />
                </Button>
              </div>
              
              {/* Password Strength Indicator */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium text-gray-600">Password Strength</span>
                  <span className={`text-sm font-medium ${
                    passwordStrength <= 1 ? 'text-red-600' : 
                    passwordStrength <= 3 ? 'text-yellow-600' : 'text-green-600'
                  }`}>
                    {getStrengthText(passwordStrength)}
                  </span>
                </div>
                <div className="h-2 flex gap-1 rounded-full overflow-hidden bg-gray-200">
                  {[...Array(5)].map((_, i) => (
                    <div
                      key={i}
                      className={`h-full flex-1 transition-all duration-300 ${
                        i < passwordStrength
                          ? getStrengthColor(passwordStrength)
                          : "bg-gray-300"
                      }`}
                    />
                  ))}
                </div>
                {issues[0] && (
                  <div className="flex items-center gap-2 text-sm text-yellow-600 bg-yellow-50 p-2 rounded-lg">
                    <span>⚠️</span>
                    <span>{issues[0]}</span>
                  </div>
                )}
              </div>
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="cryptoAlgorithm" className="text-sm font-medium text-gray-700 flex items-center">
                <Sparkles className="w-4 h-4 mr-2" />
                Encryption Algorithm
                <span title="Choose the cryptographic method for storing your password. Post-Quantum is resistant to quantum attacks!">
                  <Info className="w-4 h-4 text-blue-500 cursor-pointer ml-1" />
                </span>
              </Label>
              <Select
                id="cryptoAlgorithm"
                name="cryptoAlgorithm"
                className="w-full px-4 py-3 border border-gray-200 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-300 bg-white/50 backdrop-blur-sm text-gray-900"
                value={cryptoAlgorithm}
                onChange={(e) => setCryptoAlgorithm(e.target.value)}
                options={encryptionAlgorithms}
              />
              
              {/* Algorithm Info Card */}
              <div className={`text-xs p-3 rounded-lg border ${getAlgorithmColor(cryptoAlgorithm)}`}>
                <div className="flex items-center gap-2 mb-1">
                  {getAlgorithmIcon(cryptoAlgorithm)}
                  <span className="font-medium">{selectedAlgorithm.label}</span>
                </div>
                <p className="text-gray-600">{selectedAlgorithm.description}</p>
                {cryptoAlgorithm === "kyber-768" && (
                  <p className="text-purple-700 mt-1 font-medium">🔬 Quantum-resistant encryption</p>
                )}
                {cryptoAlgorithm === "aes-256-gcm-hybrid" && (
                  <p className="text-green-700 mt-1 font-medium">🛡️ Maximum security with dual encryption</p>
                )}
              </div>
            </div>
          </div>
          
          <DialogFooter className="pt-6">
            <Button 
              type="submit" 
              disabled={isLoading}
              className="w-full py-3 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white font-medium rounded-xl transition-all duration-300 transform hover:scale-105 shadow-lg hover:shadow-xl disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isLoading ? (
                <div className="flex items-center">
                  <LoadingSpinner size="sm" variant="shield" className="mr-2" />
                  Securing Password...
                </div>
              ) : (
                <div className="flex items-center">
                  <Shield className="mr-2 h-4 w-4" />
                  Save Password Securely
                  <ArrowRight className="ml-2 h-4 w-4" />
                </div>
              )}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
