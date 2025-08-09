"use client";

import { useEffect, useState } from "react";
import { deletePassword, getPasswords } from "@/app/server/password";
import { Button } from "@/components/ui/button";
import { EyeIcon, EyeOffIcon, TrashIcon, CopyIcon, CheckIcon, GlobeIcon, UserIcon, LockIcon, Shield } from "lucide-react";
import crypto from "node:crypto";
import type { DecryptedPassword } from "../server/helpers";
import { toast } from "sonner";

export default function PasswordList({
  passwords,
}: {
  passwords: DecryptedPassword[];
}) {
  const [visiblePasswords, setVisiblePasswords] = useState<Set<string>>(
    new Set()
  );
  const [copiedItems, setCopiedItems] = useState<Set<string>>(new Set());

  const togglePasswordVisibility = (id: string) => {
    setVisiblePasswords((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const copyToClipboard = async (text: string, type: string, id: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedItems(prev => new Set([...prev, id]));
      toast.success(`${type} copied to clipboard!`);
      setTimeout(() => {
        setCopiedItems(prev => {
          const next = new Set(prev);
          next.delete(id);
          return next;
        });
      }, 2000);
    } catch (err) {
      toast.error("Failed to copy to clipboard");
    }
  };

  const handleDelete = async (id: string, service: string) => {
    try {
      await deletePassword(id);
      toast.success(`${service} password deleted successfully`);
    } catch (error) {
      toast.error("Failed to delete password");
    }
  };

  if (passwords.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center">
        <div className="p-6 bg-gradient-to-r from-blue-100 to-purple-100 rounded-full mb-4">
          <LockIcon className="h-12 w-12 text-gray-400" />
        </div>
        <h3 className="text-xl font-semibold text-gray-700 mb-2">No passwords yet</h3>
        <p className="text-gray-500 max-w-md">
          Start building your secure vault by adding your first password. Your credentials will be encrypted and stored safely.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {passwords.map((password: DecryptedPassword) => (
        <div
          key={password.id}
          className="group relative bg-white/60 backdrop-blur-sm border border-gray-200/50 rounded-2xl p-6 hover:bg-white/80 hover:shadow-lg transition-all duration-300 hover:scale-[1.02]"
        >
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
            {/* Service Info */}
            <div className="flex items-center gap-4 flex-1">
              <div className="p-3 bg-gradient-to-r from-blue-500 to-purple-500 rounded-xl shadow-lg">
                <GlobeIcon className="h-5 w-5 text-white" />
              </div>
              <div className="flex-1">
                <h3 className="font-bold text-gray-800 text-lg mb-1">{password.service}</h3>
                                  <div className="flex flex-col sm:flex-row gap-4 text-sm">
                    <div className="flex items-center gap-2">
                      <UserIcon className="h-4 w-4 text-gray-500" />
                      <span className="text-gray-600 font-medium">Username:</span>
                      <span className="text-gray-800 font-mono">{password.username}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <LockIcon className="h-4 w-4 text-gray-500" />
                      <span className="text-gray-600 font-medium">Password:</span>
                      <span className="text-gray-800 font-mono">
                        {visiblePasswords.has(password.id)
                          ? password.password
                          : "••••••••••••••••"}
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Shield className="h-4 w-4 text-gray-500" />
                      <span className="text-gray-600 font-medium">Algorithm:</span>
                      <span className={`text-xs px-2 py-1 rounded-full font-medium ${
                        password.algorithm === 'kyber-768' ? 'bg-purple-100 text-purple-700' :
                        password.algorithm === 'aes-256-gcm' ? 'bg-blue-100 text-blue-700' :
                        password.algorithm === 'aes-256-gcm-hybrid' ? 'bg-green-100 text-green-700' :
                        'bg-gray-100 text-gray-700'
                      }`}>
                        {password.algorithm === 'kyber-768' ? 'Kyber-768 (PQ)' :
                         password.algorithm === 'aes-256-gcm' ? 'AES-256-GCM' :
                         password.algorithm === 'aes-256-gcm-hybrid' ? 'Hybrid (AES+Kyber)' :
                         password.algorithm}
                      </span>
                    </div>
                  </div>
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex items-center gap-2">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => copyToClipboard(password.username, "Username", `username-${password.id}`)}
                className="p-2 hover:bg-blue-50 hover:text-blue-600 transition-colors"
                title="Copy username"
              >
                {copiedItems.has(`username-${password.id}`) ? (
                  <CheckIcon className="h-4 w-4 text-green-600" />
                ) : (
                  <CopyIcon className="h-4 w-4" />
                )}
              </Button>
              
              <Button
                variant="ghost"
                size="sm"
                onClick={() => copyToClipboard(password.password, "Password", `password-${password.id}`)}
                className="p-2 hover:bg-blue-50 hover:text-blue-600 transition-colors"
                title="Copy password"
              >
                {copiedItems.has(`password-${password.id}`) ? (
                  <CheckIcon className="h-4 w-4 text-green-600" />
                ) : (
                  <CopyIcon className="h-4 w-4" />
                )}
              </Button>

              <Button
                variant="ghost"
                size="sm"
                onClick={() => togglePasswordVisibility(password.id)}
                className="p-2 hover:bg-purple-50 hover:text-purple-600 transition-colors"
                title={visiblePasswords.has(password.id) ? "Hide password" : "Show password"}
              >
                {visiblePasswords.has(password.id) ? (
                  <EyeOffIcon className="h-4 w-4" />
                ) : (
                  <EyeIcon className="h-4 w-4" />
                )}
              </Button>

              <Button
                variant="ghost"
                size="sm"
                onClick={() => handleDelete(password.id, password.service)}
                className="p-2 hover:bg-red-50 hover:text-red-600 transition-colors"
                title="Delete password"
              >
                <TrashIcon className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
