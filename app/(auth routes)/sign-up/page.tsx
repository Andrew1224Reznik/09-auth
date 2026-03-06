"use client";

import css from "./page.module.css";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { AxiosError } from "axios";

import { register, getMe } from "@/lib/api/clientApi";
import { type UserReg } from "@/types/user";
import { useLogin } from "@/lib/store/authStore";

import Modal from "@/components/Modal/Modal";

export default function Register() {
  const setUser = useLogin((state) => state.setUser);
  const router = useRouter();
  const [error, setError] = useState(false);
  const [isModal, setIsModal] = useState(false);

  function closeModal() {
    router.push("/sign-in");
  }

  async function handleSubmit(formData: FormData) {
    const data: UserReg = {
      email: formData.get("email") as string,
      password: formData.get("password") as string,
    };
    try {
      const res = await register(data);
      if (res) {
        const user = await getMe();
        setUser(user);
        router.push("/profile");
      }
    } catch (error: unknown) {
      if (error instanceof AxiosError) {
        if (error.response?.data?.response?.message === "User exists") {
          setIsModal(true);
        }
      }
      setError(true);
    }
  }

  return (
    <main className={css.mainContent}>
      <h1 className={css.formTitle}>Sign up</h1>
      <form className={css.form} action={handleSubmit}>
        <div className={css.formGroup}>
          <label htmlFor="email">Email</label>
          <input
            id="email"
            type="email"
            name="email"
            className={css.input}
            required
          />
        </div>

        <div className={css.formGroup}>
          <label htmlFor="password">Password</label>
          <input
            id="password"
            type="password"
            name="password"
            className={css.input}
            required
            minLength={6}
          />
        </div>

        <div className={css.actions}>
          <button type="submit" className={css.submitButton}>
            Register
          </button>
        </div>

        {error && <p className={css.error}>Error</p>}
        {isModal && (
          <Modal onClose={closeModal}>
            <p>This user is already registered. Please go to the login page.</p>
          </Modal>
        )}
      </form>
    </main>
  );
}
