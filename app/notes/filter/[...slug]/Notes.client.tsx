"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useDebounce } from "../../../hooks/useDebounce";

import SearchBox from "../../../../components/SearchBox/SearchBox";
import NoteList from "../../../../components/NoteList/NoteList";
import Pagination from "../../../../components/Pagination/Pagination";
import { NoteTag } from "../../../../types/note";
import Link from "next/link";

import { fetchNotes } from "../../../../lib/api";
import css from "./NotesPage.module.css";

type NotesClientProps = {
  tag?: NoteTag;
};

export default function NotesClient({ tag }: NotesClientProps) {
  const [search, setSearch] = useState("");
  const debouncedSearch = useDebounce(search, 500);
  const [currentPage, setCurrentPage] = useState(1);
  const perPage = 12;

  const { data, isLoading, isError } = useQuery({
    queryKey: ["notes", currentPage, debouncedSearch, tag],
    queryFn: () => fetchNotes(currentPage, perPage, debouncedSearch, tag),
    placeholderData: (previousData) => previousData,
  });

  const handleSearch = (newSearch: string) => {
    setSearch(newSearch);
    setCurrentPage(1);
  };

  const notes = data?.notes ?? [];
  const totalPages = data?.totalPages ?? 0;

  return (
    <div className={css.app}>
      <header className={css.toolbar}>
        <SearchBox onSubmit={handleSearch} />
        {totalPages > 1 && (
          <Pagination
            currentPage={currentPage}
            totalPages={totalPages}
            onPageChange={setCurrentPage}
          />
        )}
        <Link href="/notes/action/create" className={css.button}>
          Create note +
        </Link>{" "}
      </header>

      {isLoading && <p>Loading data, please wait...</p>}
      {isError && <p>Whoops, something went wrong! Please try again</p>}

      {notes.length > 0 && <NoteList notes={notes} />}
    </div>
  );
}
