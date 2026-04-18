import { useAuth } from '../contexts/AuthContext';

export default function Header() {
  const { logout } = useAuth();
  return (
    <header className="bg-white shadow-sm py-3 px-6 flex justify-between items-center">
      <h1 className="text-xl font-semibold text-gray-800">Admin Console</h1>
      <button
        onClick={logout}
        className="rounded-md border px-3 py-1 text-gray-600 hover:text-gray-900"
      >
        Logout
      </button>
    </header>
  );
}
