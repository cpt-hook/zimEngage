import { useRouter } from 'next/router'
import { useAuthContext } from '@/contexts/AuthContext'
import { useEffect } from 'react'

export function ProtectedRoute({ children }) {
  const router = useRouter()
  const { user, isLoading } = useAuthContext()

  useEffect(() => {
    if (!isLoading && !user) {
      router.push('/login')
    }
  }, [isLoading, user, router])

  if (isLoading) {
    return <div>Loading...</div>
  }

  return user ? children : null
} 