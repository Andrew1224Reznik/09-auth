import {
  QueryClient,
  HydrationBoundary,
  dehydrate,
} from "@tanstack/react-query";
import { Metadata } from "next";

import { FetchTagNote } from "@/types/note";
import { fetchNotes } from "@/lib/api/serverApi";
import NotesClient from "./Notes.client";

import css from "./page.module.css";

interface NotesProps {
  params: Promise<{ slug: string[] }>;
}

export async function generateMetadata({
  params,
}: NotesProps): Promise<Metadata> {
  const { slug } = await params;
  const tag = slug[0];

  return {
    title: `${tag}`,
    description: `Page for ${tag} tag`,
    openGraph: {
      title: `${tag}`,
      description: `Page for ${tag} tag`,
      url: "https://08-zustand-eight-rho.vercel.app/",
      images: [
        {
          url: "https://ac.goit.global/fullstack/react/notehub-og-meta.jpg",
          width: 1200,
          height: 630,
          alt: "logo",
        },
      ],
    },
  };
}

export default async function Notes({ params }: NotesProps) {
  const queryClient = new QueryClient();

  const { slug } = await params;
  const tag = slug[0] as FetchTagNote;

  await queryClient.prefetchQuery({
    queryKey: ["notes", tag, 1, ""],
    queryFn: () => fetchNotes(tag, 1, ""),
  });

  return (
    <main className={css.main}>
      <HydrationBoundary state={dehydrate(queryClient)}>
        <NotesClient tag={tag} />
      </HydrationBoundary>
    </main>
  );
}
