import {
  QueryClient,
  dehydrate,
  HydrationBoundary,
} from "@tanstack/react-query";
import NotesClient from "./Notes.client";
import { fetchNotes } from "../../../../lib/api";
import type { NoteTag } from "../../../../types/note";
import type { Metadata } from "next";

type Props = {
  params: Promise<{ slug: string[] }>;
};

const allTags: NoteTag[] = ["Work", "Personal", "Meeting", "Shopping", "Todo"];

function getFirstTag(slug: string[] | undefined): NoteTag | undefined {
  if (!slug || slug[0] === "All") return undefined;
  return allTags.includes(slug[0] as NoteTag)
    ? (slug[0] as NoteTag)
    : undefined;
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { slug } = await params;

  const firstTag = getFirstTag(slug);

  return {
    title: firstTag ? `${firstTag} notes` : "All notes",
    description: firstTag
      ? `Notes in the ${firstTag} category`
      : "All your notes",
    openGraph: {
      title: firstTag ? `${firstTag} notes` : "All notes",
      description: firstTag
        ? `Notes in the ${firstTag} category`
        : "All your notes",
      url: `https://notehub.com/notes/${firstTag ?? "All"}`,
      siteName: "NoteHub",
      images: [
        {
          url: "https://ac.goit.global/fullstack/react/notehub-og-meta.jpg",
          width: 1200,
          height: 630,
          alt: "NoteHub image",
        },
      ],
      type: "article",
    },
  };
}

export default async function NotesPage({ params }: Props) {
  const { slug } = await params;

  const firstTag = getFirstTag(slug);

  const page = 1;
  const perPage = 12;
  const search = "";

  const queryClient = new QueryClient();

  await queryClient.prefetchQuery({
    queryKey: ["notes", { page, perPage, search, tag: firstTag }],
    queryFn: () => fetchNotes(page, perPage, search, firstTag),
  });

  return (
    <HydrationBoundary state={dehydrate(queryClient)}>
      <NotesClient tag={firstTag} />
    </HydrationBoundary>
  );
}
