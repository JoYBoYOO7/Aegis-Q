import { cn } from "@/lib/utils";
import { Loader2, Shield, Sparkles } from "lucide-react";

interface LoadingSpinnerProps {
  size?: "sm" | "md" | "lg";
  variant?: "default" | "shield" | "sparkles";
  className?: string;
}

export function LoadingSpinner({ 
  size = "md", 
  variant = "default",
  className 
}: LoadingSpinnerProps) {
  const sizeClasses = {
    sm: "w-4 h-4",
    md: "w-6 h-6", 
    lg: "w-8 h-8"
  };

  const iconSize = {
    sm: "w-3 h-3",
    md: "w-4 h-4",
    lg: "w-5 h-5"
  };

  if (variant === "shield") {
    return (
      <div className={cn("relative", className)}>
        <div className={cn("animate-spin", sizeClasses[size])}>
          <Shield className={cn("text-blue-600", iconSize[size])} />
        </div>
        <div className={cn("absolute inset-0 animate-ping", sizeClasses[size])}>
          <Shield className={cn("text-blue-400 opacity-20", iconSize[size])} />
        </div>
      </div>
    );
  }

  if (variant === "sparkles") {
    return (
      <div className={cn("relative", className)}>
        <div className={cn("animate-spin", sizeClasses[size])}>
          <Sparkles className={cn("text-purple-600", iconSize[size])} />
        </div>
        <div className={cn("absolute inset-0 animate-ping", sizeClasses[size])}>
          <Sparkles className={cn("text-purple-400 opacity-20", iconSize[size])} />
        </div>
      </div>
    );
  }

  return (
    <Loader2 className={cn("animate-spin", sizeClasses[size], className)} />
  );
}
