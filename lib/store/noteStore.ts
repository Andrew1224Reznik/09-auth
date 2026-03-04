import { create } from "zustand";
import { persist } from "zustand/middleware";
import { CreateNoteData } from "../api";

interface NoteStore {
  draft: CreateNoteData;
  setDraft: (note: CreateNoteData) => void;
  clearDraft: () => void;
}

const initialDraft: CreateNoteData = {
  title: "",
  content: "",
  tag: "Todo",
};

export const useNoteStore = create<NoteStore>()(
  persist(
    (set) => ({
      draft: initialDraft,
      setDraft: (note) => set(() => ({ draft: note })),
      clearDraft: () => set(() => ({ draft: initialDraft })),
    }),
    {
      name: "note-draft",
      partialize: (state) => ({ draft: state.draft }),
    }
  )
);
