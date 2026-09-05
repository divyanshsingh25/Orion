export function SimplePage({ title, subtitle }: { title: string; subtitle: string }) {
  return (
    <div>
      <h1 className="text-[37px] font-extrabold leading-none">{title}</h1>
      <p className="muted-copy mt-5">{subtitle}</p>
      <section className="panel mt-[33px] px-[30px] py-[29px]">
        <h2 className="text-[20px] font-extrabold">Overview</h2>
        <p className="mt-2 text-[17px] font-medium text-muted-foreground">No additional data available for this view.</p>
      </section>
    </div>
  );
}