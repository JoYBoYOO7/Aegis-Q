"use client";
import type { Password, User } from "@prisma/client";
import { Button } from "@/components/ui/button";
import { PlusIcon, KeyIcon, ShieldCheckIcon, UserIcon, LockIcon, SparklesIcon, LogOutIcon } from "lucide-react";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import { useState } from "react";
import AddPasswordDialog from "./add-password-dialog";
import PasswordList from "./password-list";
import type { DecryptedPassword } from "../server/helpers";
import { logoutUser } from "../server/user";
import { useRouter } from "next/navigation";
import { toast } from "sonner";

interface DashboardProps {
  user: User;
  passwords: DecryptedPassword[];
}

export default function Dashboard({ user, passwords }: DashboardProps) {
  const [isAddPasswordOpen, setIsAddPasswordOpen] = useState(false);
  const [isLoggingOut, setIsLoggingOut] = useState(false);
  const router = useRouter();

  const handleLogout = async () => {
    setIsLoggingOut(true);
    try {
      try {
        await logoutUser();
      } catch (e) {
        console.warn("Logout request issue:", e);
      }
      toast.success("Logged out successfully");
      // Use window.location.href for a full page reload to ensure proper redirect
      window.location.href = "/login";
    } catch (error) {
      toast.error("Failed to logout");
      console.error("Logout failed:", error);
    } finally {
      setIsLoggingOut(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50 p-6">
      <div className="container mx-auto space-y-8">
        {/* Header Section */}
        <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-6">
          <div className="space-y-2">
            <div className="flex items-center gap-3">
              <div className="p-3 bg-gradient-to-r from-blue-600 to-purple-600 rounded-2xl shadow-lg">
                <ShieldCheckIcon className="h-8 w-8 text-white" />
              </div>
              <div>
                <h1 className="text-4xl font-bold bg-gradient-to-r from-gray-800 to-gray-600 bg-clip-text text-transparent">
                  SecureVault
                </h1>
                <p className="text-gray-600 font-medium">Your Digital Fortress</p>
              </div>
            </div>
            <div className="flex items-center gap-2 text-gray-600">
              <UserIcon className="h-4 w-4" />
              <span>Welcome back, <span className="font-semibold text-gray-800">{user.name}</span></span>
            </div>
          </div>
          
          <div className="flex items-center gap-3">
            <Button 
              onClick={() => setIsAddPasswordOpen(true)}
              className="bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white font-medium px-6 py-3 rounded-xl shadow-lg hover:shadow-xl transition-all duration-300 transform hover:scale-105"
            >
              <PlusIcon className="mr-2 h-5 w-5" />
              Add Password
            </Button>
            
            <Button 
              onClick={handleLogout}
              disabled={isLoggingOut}
              className="bg-gradient-to-r from-red-500 to-red-600 hover:from-red-600 hover:to-red-700 text-white font-medium px-4 py-3 rounded-xl shadow-lg hover:shadow-xl transition-all duration-300"
            >
              <LogOutIcon className="mr-2 h-4 w-4" />
              {isLoggingOut ? "Logging out..." : "Logout"}
            </Button>
          </div>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <Card className="border-0 shadow-xl bg-white/80 backdrop-blur-sm hover:shadow-2xl transition-all duration-300">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Total Passwords</p>
                  <p className="text-3xl font-bold text-gray-800">{passwords.length}</p>
                </div>
                <div className="p-3 bg-blue-100 rounded-xl">
                  <KeyIcon className="h-6 w-6 text-blue-600" />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="border-0 shadow-xl bg-white/80 backdrop-blur-sm hover:shadow-2xl transition-all duration-300">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Security Level</p>
                  <p className="text-3xl font-bold text-gray-800">AES-256</p>
                </div>
                <div className="p-3 bg-green-100 rounded-xl">
                  <LockIcon className="h-6 w-6 text-green-600" />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="border-0 shadow-xl bg-white/80 backdrop-blur-sm hover:shadow-2xl transition-all duration-300">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Last Updated</p>
                  <p className="text-3xl font-bold text-gray-800">Today</p>
                </div>
                <div className="p-3 bg-purple-100 rounded-xl">
                  <SparklesIcon className="h-6 w-6 text-purple-600" />
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Passwords Section */}
        <Card className="border-0 shadow-2xl bg-white/80 backdrop-blur-sm">
          <CardHeader className="pb-6">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-gradient-to-r from-blue-500 to-purple-500 rounded-lg">
                <KeyIcon className="h-5 w-5 text-white" />
              </div>
              <div>
                <CardTitle className="text-2xl font-bold text-gray-800">Stored Passwords</CardTitle>
                <CardDescription className="text-gray-600">
                  Your securely encrypted credentials are protected with military-grade encryption
                </CardDescription>
              </div>
            </div>
          </CardHeader>
          <CardContent className="h-[calc(100vh-24rem)] overflow-y-auto">
            <PasswordList passwords={passwords} />
          </CardContent>
        </Card>

        <AddPasswordDialog
          open={isAddPasswordOpen}
          onOpenChange={setIsAddPasswordOpen}
        />
      </div>
    </div>
  );
}
