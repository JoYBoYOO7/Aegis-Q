import { NextRequest, NextResponse } from 'next/server'
import { getEncryptionStats, rotateEncryptionKeys } from '@/app/server/password'
import { logSecurityEvent } from '@/app/server/security'

export async function GET(request: NextRequest) {
  try {
    const stats = await getEncryptionStats()
    
    logSecurityEvent("encryption_stats_retrieved", undefined, { stats })
    
    return NextResponse.json({
      success: true,
      data: stats
    })
  } catch (error) {
    console.error('Failed to get encryption stats:', error)
    
    logSecurityEvent("encryption_stats_failed", undefined, { 
      error: error instanceof Error ? error.message : 'Unknown error' 
    })
    
    return NextResponse.json(
      { 
        success: false, 
        error: 'Failed to retrieve encryption statistics' 
      },
      { status: 500 }
    )
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { action } = body

    if (action === 'rotate-keys') {
      const result = await rotateEncryptionKeys()
      
      logSecurityEvent("encryption_keys_rotated", undefined, { result })
      
      return NextResponse.json({
        success: true,
        data: result,
        message: 'Encryption keys rotated successfully'
      })
    }

    return NextResponse.json(
      { 
        success: false, 
        error: 'Invalid action' 
      },
      { status: 400 }
    )
  } catch (error) {
    console.error('Failed to perform encryption action:', error)
    
    logSecurityEvent("encryption_action_failed", undefined, { 
      error: error instanceof Error ? error.message : 'Unknown error' 
    })
    
    return NextResponse.json(
      { 
        success: false, 
        error: 'Failed to perform encryption action' 
      },
      { status: 500 }
    )
  }
}
