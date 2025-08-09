"use client";

import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";
import { registerUser } from "@/app/server/user";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Eye, EyeOff, Mail, Lock, User, ArrowRight, CheckCircle, Shield } from "lucide-react";
import { LoadingSpinner } from "@/components/ui/loading-spinner";

export function RegisterForm({
  className,
  ...props
}: React.ComponentPropsWithoutRef<"div">) {
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [passwordMatch, setPasswordMatch] = useState(true);
  const router = useRouter();

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setIsLoading(true);
    
    const formData = new FormData(e.currentTarget);
    const password = formData.get("password") as string;
    const confirmPassword = formData.get("confirmPassword") as string;
    const email = formData.get("email") as string;
    const name = formData.get("name") as string;
    
    if (password !== confirmPassword) {
      setPasswordMatch(false);
      toast.error("Passwords do not match");
      setIsLoading(false);
      return;
    }
    
    try {
      setPasswordMatch(true);
      const registerPromise = registerUser({ email, password, name });

      toast.promise(registerPromise, {
        loading: "Creating your secure vault with advanced encryption...",
        success: "Account created successfully! Welcome to SecureVault! 🎉",
        error: "Failed to create account. Please try again.",
      });

      const result = await registerPromise;
      console.log("Registration successful:", result);
      toast.success("Account created! Redirecting to dashboard...");
      // Force a hard refresh to ensure the dashboard loads with the new session
      setTimeout(() => {
        window.location.href = "/dashboard";
      }, 1500);
    } catch (error) {
      console.error("Registration failed:", error);
    } finally {
      setIsLoading(false);
    }
  };

  const handlePasswordChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const password = e.target.value;
    const confirmPassword = (e.target.form?.querySelector('[name="confirmPassword"]') as HTMLInputElement)?.value;
    if (confirmPassword) {
      setPasswordMatch(password === confirmPassword);
    }
  };

  const handleConfirmPasswordChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const confirmPassword = e.target.value;
    const password = (e.target.form?.querySelector('[name="password"]') as HTMLInputElement)?.value;
    setPasswordMatch(password === confirmPassword);
  };

  return (
    <div className={cn("flex flex-col gap-6", className)} {...props}>
      <Card className="border-0 shadow-2xl bg-white/80 backdrop-blur-sm">
        <CardHeader className="text-center pb-6">
          <div className="flex items-center justify-center mb-4">
            <div className="p-3 bg-gradient-to-r from-purple-600 to-pink-600 rounded-2xl shadow-lg">
              <Shield className="h-8 w-8 text-white" />
            </div>
          </div>
          <CardTitle className="text-3xl font-bold bg-gradient-to-r from-gray-800 to-gray-600 bg-clip-text text-transparent">
            Join SecureVault
          </CardTitle>
          <CardDescription className="text-gray-600 text-lg">
            Create your digital fortress with military-grade security
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="name" className="text-sm font-medium text-gray-700 flex items-center">
                  <User className="w-4 h-4 mr-2" />
                  Full Name
                </Label>
                <Input 
                  id="name" 
                  name="name" 
                  placeholder="Enter your full name" 
                  required 
                  className="w-full px-4 py-3 border border-gray-200 rounded-xl focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all duration-300 bg-white/50 backdrop-blur-sm text-gray-900 placeholder:text-gray-500"
                />
              </div>
              
              <div className="space-y-2">
                <Label htmlFor="email" className="text-sm font-medium text-gray-700 flex items-center">
                  <Mail className="w-4 h-4 mr-2" />
                  Email Address
                </Label>
                <Input
                  id="email"
                  type="email"
                  name="email"
                  placeholder="Enter your email"
                  required
                  className="w-full px-4 py-3 border border-gray-200 rounded-xl focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all duration-300 bg-white/50 backdrop-blur-sm text-gray-900 placeholder:text-gray-500"
                />
              </div>
              
              <div className="space-y-2">
                <Label htmlFor="password" className="text-sm font-medium text-gray-700 flex items-center">
                  <Lock className="w-4 h-4 mr-2" />
                  Password
                </Label>
                <div className="relative">
                  <Input 
                    id="password" 
                    name="password" 
                    type={showPassword ? "text" : "password"}
                    placeholder="Create a strong password"
                    required 
                    onChange={handlePasswordChange}
                    className="w-full px-4 py-3 pr-12 border border-gray-200 rounded-xl focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all duration-300 bg-white/50 backdrop-blur-sm text-gray-900 placeholder:text-gray-500"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600 transition-colors duration-200"
                  >
                    {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                  </button>
                </div>
              </div>
              
              <div className="space-y-2">
                <Label htmlFor="confirmPassword" className="text-sm font-medium text-gray-700 flex items-center">
                  <Lock className="w-4 h-4 mr-2" />
                  Confirm Password
                </Label>
                <div className="relative">
                  <Input
                    id="confirmPassword"
                    name="confirmPassword"
                    type={showConfirmPassword ? "text" : "password"}
                    placeholder="Confirm your password"
                    required
                    onChange={handleConfirmPasswordChange}
                    className={`w-full px-4 py-3 pr-12 border rounded-xl focus:ring-2 focus:border-transparent transition-all duration-300 bg-white/50 backdrop-blur-sm text-gray-900 placeholder:text-gray-500 ${
                      passwordMatch ? 'border-gray-200 focus:ring-purple-500' : 'border-red-300 focus:ring-red-500'
                    }`}
                  />
                  <button
                    type="button"
                    onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                    className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600 transition-colors duration-200"
                  >
                    {showConfirmPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                  </button>
                  {!passwordMatch && (
                    <div className="absolute right-12 top-1/2 transform -translate-y-1/2">
                      <div className="w-5 h-5 bg-red-100 rounded-full flex items-center justify-center">
                        <div className="w-2 h-2 bg-red-500 rounded-full"></div>
                      </div>
                    </div>
                  )}
                  {passwordMatch && (
                    <div className="absolute right-12 top-1/2 transform -translate-y-1/2">
                      <CheckCircle className="w-5 h-5 text-green-500" />
                    </div>
                  )}
                </div>
                {!passwordMatch && (
                  <p className="text-sm text-red-600 flex items-center gap-1">
                    <span>⚠️</span>
                    Passwords do not match
                  </p>
                )}
              </div>
            </div>

            <Button 
              type="submit" 
              className="w-full py-3 bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 text-white font-medium rounded-xl transition-all duration-300 transform hover:scale-105 shadow-lg hover:shadow-xl disabled:opacity-50 disabled:cursor-not-allowed"
              disabled={isLoading || !passwordMatch}
            >
              {isLoading ? (
                <div className="flex items-center">
                  <LoadingSpinner size="sm" variant="sparkles" className="mr-2" />
                  Creating Your Vault...
                </div>
              ) : (
                <div className="flex items-center">
                  <Shield className="mr-2 h-4 w-4" />
                  Create Secure Account
                  <ArrowRight className="ml-2 w-4 h-4" />
                </div>
              )}
            </Button>
          </form>
          
          <div className="mt-6 text-center">
            <p className="text-sm text-gray-600">
              Already have an account?{" "}
              <a 
                href="/login" 
                className="text-purple-600 hover:text-purple-700 font-medium transition-colors duration-300 underline-offset-4 hover:underline"
              >
                Sign in here
              </a>
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
