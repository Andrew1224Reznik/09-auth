"use client";

import css from "./NoteForm.module.css";

import { useId } from "react";
import { useRouter } from "next/navigation";
import { useMutation, useQueryClient } from "@tanstack/react-query";

import { createNote } from "@/lib/api/clientApi";
import { type NewNote } from "@/types/note";
import { useDraft } from "@/lib/store/noteStore";

type noteTag = "Todo" | "Work" | "Personal" | "Meeting" | "Shopping";

export default function NoteForm() {
  const id = useId();
  const router = useRouter();
  const queryClient = useQueryClient();
  const { note, setDraft, clearDraft } = useDraft();

  const createMutation = useMutation({
    mutationFn: async (data: NewNote) => {
      const res = await createNote(data);
      return res;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["notes"] });
      clearDraft();
      successForm();
    },
  });

  function change(
    ev: React.ChangeEvent<
      HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement
    >
  ) {
    const data = { ...note, [ev.target.name]: ev.target.value };
    setDraft(data);
  }

  function cancelForm() {
    router.back();
  }

  function successForm() {
    router.push("/notes/filter/all");
  }

  function handleSubmit(formDada: FormData) {
    const newNote: NewNote = {
      title: formDada.get("title") as string,
      content: formDada.get("content") as string,
      tag: formDada.get("tag") as noteTag,
    };
    createMutation.mutate(newNote);
  }

  return (
    <form className={css.form} action={handleSubmit}>
      <div className={css.formGroup}>
        <label htmlFor={`${id}-title`}>Title</label>
        <input
          onChange={change}
          type="text"
          id={`${id}-title`}
          name="title"
          className={css.input}
          required
          defaultValue={note.title}
        />
      </div>

      <div className={css.formGroup}>
        <label htmlFor={`${id}-content`}>Content</label>
        <textarea
          onChange={change}
          id={`${id}-content`}
          name="content"
          className={css.textarea}
          rows={8}
          defaultValue={note.content}
        />
      </div>

      <div className={css.formGroup}>
        <label htmlFor={`${id}-tag`}>Tag</label>
        <select
          onChange={change}
          id={`${id}-tag`}
          name="tag"
          className={css.select}
          defaultValue={note.tag}
        >
          <option value="Todo">Todo</option>
          <option value="Work">Work</option>
          <option value="Personal">Personal</option>
          <option value="Meeting">Meeting</option>
          <option value="Shopping">Shopping</option>
        </select>
      </div>

      <div className={css.actions}>
        <button onClick={cancelForm} type="button" className={css.cancelButton}>
          Cancel
        </button>
        <button type="submit" className={css.submitButton}>
          Create note
        </button>
      </div>
    </form>
  );
}
