import { cookies } from "next/headers";
import { nextServer } from "./api";

import type { User } from "@/types/user";
import { type Note, type FetchTagNote } from "@/types/note";

interface Answer {
  notes: Note[];
  totalPages: number;
}

export async function fetchNotes(
  tag: FetchTagNote,
  page: number,
  search: string
): Promise<Answer> {
  const cookieStore = await cookies();
  if (tag === "all" && !search) {
    const res = await nextServer.get<Answer>(
      `/notes?&page=${page}&perPage=12`,
      {
        headers: {
          Cookie: cookieStore.toString(),
        },
      }
    );
    return res.data;
  }

  if (tag !== "all" && !search) {
    const res = await nextServer.get<Answer>(
      `/notes?tag=${tag}&page=${page}&perPage=12`,
      {
        headers: {
          Cookie: cookieStore.toString(),
        },
      }
    );
    return res.data;
  }

  if (tag === "all" && search) {
    const res = await nextServer.get<Answer>(
      `/notes?search=${search}&page=${page}&perPage=12`,
      {
        headers: {
          Cookie: cookieStore.toString(),
        },
      }
    );
    return res.data;
  }

  const res = await nextServer.get<Answer>(
    `/notes?search=${search}&tag=${tag}&page=${page}&perPage=12`,
    {
      headers: {
        Cookie: cookieStore.toString(),
      },
    }
  );
  return res.data;
}

export async function fetchNoteById(id: string): Promise<Note> {
  const cookieStore = await cookies();

  const res = await nextServer.get<Note>(`/notes/${id}`, {
    headers: {
      Cookie: cookieStore.toString(),
    },
  });
  return res.data;
}

export async function getMe(): Promise<User> {
  const cookieStore = await cookies();

  const res = await nextServer.get("/users/me", {
    headers: {
      Cookie: cookieStore.toString(),
    },
  });
  return res.data;
}

export async function checkSession() {
  const cookieStore = await cookies();

  const res = await nextServer.get("/auth/session", {
    headers: {
      Cookie: cookieStore.toString(),
    },
  });
  return res;
}
