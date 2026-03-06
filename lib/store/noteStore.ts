import { create } from "zustand";
import { persist } from "zustand/middleware";

import { NewNote } from "@/types/note";

interface NoteDraft {
  note: NewNote;
  setDraft: (obj: NewNote) => void;
  clearDraft: () => void;
}

const initialDraft: NewNote = {
  title: "",
  content: "",
  tag: "Todo",
};

export const useDraft = create<NoteDraft>()(
  persist(
    (set) => ({
      note: initialDraft,
      setDraft: (newDraft) => set(() => ({ note: newDraft })),
      clearDraft: () => set(() => ({ note: initialDraft })),
    }),
    {
      name: "note-draft",
      partialize: (state) => ({ note: state.note }),
    }
  )
);
