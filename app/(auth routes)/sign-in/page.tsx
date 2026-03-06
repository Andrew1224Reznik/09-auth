"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { AxiosError } from "axios";

import { UserReg } from "@/types/user";
import { login, getMe } from "@/lib/api/clientApi";
import { useLogin } from "@/lib/store/authStore";

import Modal from "@/components/Modal/Modal";
import css from "./page.module.css";

export default function Login() {
  const setUser = useLogin((state) => state.setUser);
  const router = useRouter();
  const [isModal, setIsModal] = useState(false);
  const [mess, setMess] = useState("");

  function closeModal() {
    router.push("/sign-up");
  }

  async function handleSubmit(formData: FormData) {
    const data: UserReg = {
      email: formData.get("email") as string,
      password: formData.get("password") as string,
    };

    try {
      const res = await login(data);
      if (res) {
        setMess("");
        const user = await getMe();
        setUser(user);
        router.push("/profile");
      }
    } catch (error) {
      if (error instanceof AxiosError) {
        if (error.response?.data?.response?.message === "Invalid credentials") {
          setIsModal(true);
        }
        setMess(error.response?.data?.response?.message);
      }
      setMess("An error has occurred. We apologize...");
    }
  }

  return (
    <main className={css.mainContent}>
      <form className={css.form} action={handleSubmit}>
        <h1 className={css.formTitle}>Sign in</h1>

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
            Log in
          </button>
        </div>

        {mess !== "" && <p className={css.error}>{mess}</p>}
        {isModal && (
          <Modal onClose={closeModal}>
            <p>Invalid credentials or user not found.</p>
          </Modal>
        )}
      </form>
    </main>
  );
}
