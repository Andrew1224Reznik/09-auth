import { type Note, type NewNote, type FetchTagNote } from "@/types/note";
import { type User, type UserReg } from "@/types/user";
import { nextServer } from "./api";

interface Answer {
  notes: Note[];
  totalPages: number;
}

interface UpdateUser {
  email: string;
  username: string;
}

export async function fetchNotes(
  tag: FetchTagNote,
  page: number,
  search: string
): Promise<Answer> {
  if (tag === "all" && !search) {
    const res = await nextServer.get<Answer>(`/notes?&page=${page}&perPage=12`);
    return res.data;
  }

  if (tag !== "all" && !search) {
    const res = await nextServer.get<Answer>(
      `/notes?tag=${tag}&page=${page}&perPage=12`
    );
    return res.data;
  }

  if (tag === "all" && search) {
    const res = await nextServer.get<Answer>(
      `/notes?search=${search}&page=${page}&perPage=12`
    );
    return res.data;
  }

  const res = await nextServer.get<Answer>(
    `/notes?search=${search}&tag=${tag}&page=${page}&perPage=12`
  );
  return res.data;
}

export async function createNote(note: NewNote): Promise<Note> {
  const res = await nextServer.post<Note>(`/notes`, note);
  return res.data;
}

export async function deleteNote(id: string): Promise<Note> {
  const res = await nextServer.delete<Note>(`/notes/${id}`);
  return res.data;
}

export async function fetchNoteById(id: string): Promise<Note> {
  const res = await nextServer.get<Note>(`/notes/${id}`);
  return res.data;
}

export async function register(data: UserReg): Promise<User> {
  const res = await nextServer.post<User>("/auth/register", data);
  return res.data;
}

export async function login(data: UserReg): Promise<User> {
  const res = await nextServer.post<User>("/auth/login", data);
  return res.data;
}

export async function logout() {
  const res = await nextServer.post("/auth/logout");
  return res.data;
}

export async function checkSession() {
  const res = await nextServer.get("/auth/session");
  return res.data;
}

export async function getMe(): Promise<User> {
  const res = await nextServer.get<User>("/users/me");
  return res.data;
}

export async function updateMe(data: UpdateUser): Promise<User> {
  const res = await nextServer.patch<User>("/users/me", data);
  return res.data;
}
