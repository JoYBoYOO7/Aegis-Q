'use server'

import prisma from "@/lib/prisma"
import { cookies } from "next/headers"
import { hashPassword, verifyPassword, verifyToken } from "./helpers"
import { generateToken } from "./helpers"

type UserRegistration = {
  email: string
  password: string
  name: string
}

type UserLogin = {
  email: string
  password: string
}
/*
 * Register a new user
 */
export async function registerUser(userData: UserRegistration) {
  // Check if user already exists
  const existingUser = await prisma.user.findUnique({
    where: { email: userData.email }
  })

  if (existingUser) {
    throw new Error("User already exists")
  }

  // Hash the password
  const hashedPassword = await hashPassword(userData.password)

  // Create the user
  const user = await prisma.user.create({
    data: {
      email: userData.email,
      password: hashedPassword,
      name: userData.name
    }
  })
  const token: string = generateToken({ userId: user.id, email: user.email });

  // Set JWT token in HTTP-only cookie
  (await cookies()).set('auth-token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 60 * 60 * 24 // 24 hours
  })

  return user
}

/**
 * Login a user
 */
export async function loginUser(credentials: UserLogin) {
  // Find the user
  const user = await prisma.user.findUnique({
    where: { email: credentials.email }
  })

  if (!user) {
    throw new Error("Invalid credentials")
  }

  // Verify password
  const passwordValid = await verifyPassword(credentials.password, user.password)
  if (!passwordValid) {
    throw new Error("Invalid credentials")
  }

  // Generate JWT token
  const token: string = generateToken({ userId: user.id, email: user.email });

  // Set JWT token in HTTP-only cookie
  (await cookies()).set('auth-token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 60 * 60 * 24 // 24 hours
  })

  return { userId: user.id, email: user.email }
}

/**
 * Get the current user from the JWT token
 */
export async function getCurrentUser() {
  const token = (await cookies()).get('auth-token')

  if (!token) {
    return null
  }

  try {
    const decoded = verifyToken(token.value)
    if (!decoded) {
      return null
    }
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId }
    })

    if (!user) {
      return null
    }

    return user
  } catch {
    return null
  }
}

/**
 * Logout user by removing the JWT token
 */
export async function logoutUser() {
  try {
    const cookieStore = await cookies();
    cookieStore.delete('auth-token');
    return { success: true };
  } catch (error) {
    console.error("Logout error:", error);
    throw new Error("Failed to logout");
  }
}