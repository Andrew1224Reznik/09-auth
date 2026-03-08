"use client";

import css from "./page.module.css";

import { useRouter } from "next/navigation";
import Image from "next/image";

import { useLogin } from "@/lib/store/authStore";
import { updateMe, getMe } from "@/lib/api/clientApi";

interface UpdateUser {
  email: string;
  username: string;
}

export default function Edit() {
  const user = useLogin((state) => state.user);
  const setUser = useLogin((state) => state.setUser);
  const router = useRouter();

  function cancel() {
    router.push("/profile");
  }

  async function handleSubmit(formData: FormData) {
    const newUser: UpdateUser = {
      email: user.email,
      username: formData.get("username") as string,
    };

    const res = await updateMe(newUser);
    if (res) {
      const updatedUser = await getMe();
      setUser(updatedUser);
      router.push("/profile");
    }
  }

  return (
    <main className={css.mainContent}>
      <div className={css.profileCard}>
        <h1 className={css.formTitle}>Edit Profile</h1>

        <Image
          src={user.avatar}
          alt="User Avatar"
          width={120}
          height={120}
          className={css.avatar}
        />

        <form className={css.profileInfo} action={handleSubmit}>
          <div className={css.usernameWrapper}>
            <label htmlFor="username">Username:</label>
            <input
              id="username"
              name="username"
              type="text"
              className={css.input}
              defaultValue={user.username}
            />
          </div>

          <p>Email: {user.email}</p>

          <div className={css.actions}>
            <button type="submit" className={css.saveButton}>
              Save
            </button>
            <button onClick={cancel} type="button" className={css.cancelButton}>
              Cancel
            </button>
          </div>
        </form>
      </div>
    </main>
  );
}
