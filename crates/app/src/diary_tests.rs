use super::*;

fn fixture(content: String) -> Result<(crate::test_lock::Isolate, LocalStore, SessionKeys)> {
    let isolate = crate::test_lock::Isolate::new()?;
    let store = LocalStore::open(&isolate.path().join("diary.db"))?;
    let keys = SessionKeys::from_urk([37; 32])?;
    let entry = MemoryEntry {
        id: "synthetic-diary-source".into(),
        kind: crate::Kind::Time,
        tags: vec![],
        title: "Synthetic diary".into(),
        content,
        user: "synthetic".into(),
        computer: "fixture".into(),
        project: "fixture".into(),
        created_at: "2026-10-27T09:00:00Z".into(),
        updated_at: "2026-10-27T09:00:00Z".into(),
        emotion: -1.0,
        parent_id: String::new(),
        importance: "trivial".into(),
        device: "fixture".into(),
        modified_by: "fixture".into(),
        supersedes: String::new(),
        superseded_by: String::new(),
        see_also: vec![],
    };
    let stored = MemoryEngine::seal(
        &keys,
        &core_sdk::search::HashingEmbedder::new(8),
        &entry,
        "synthetic",
    )?;
    assert!(store.put(&stored)?);
    Ok((isolate, store, keys))
}

#[test]
fn lexical_finds_long_keyword_across_index_fragment_boundary() -> Result<()> {
    let query: String = (0..200)
        .map(|n| char::from_u32(0x4e00 + n).unwrap())
        .collect();
    let content = format!("{}{}{}", "x".repeat(700), query, "x".repeat(700));
    let (_isolate, store, keys) = fixture(content.clone())?;
    let result = search(&store, &keys, &query, 5, 4000, false)?;
    assert!(
        !result.items.is_empty(),
        "full-text keyword must not disappear at an indexing boundary"
    );
    assert!(result.items[0].text.contains(&query));
    let hit = &result.items[0];
    assert_eq!(
        hit.text,
        content
            .chars()
            .skip(hit.start)
            .take(hit.end - hit.start)
            .collect::<String>()
    );
    let read = read_fragment(&store, &keys, &hit.source_id, &hit.fragment_id, 0, 4000)?;
    assert!(read.items.iter().any(|item| item.text.contains(&query)));
    Ok(())
}

#[test]
fn lexical_does_not_depend_on_corrupt_derived_cache() -> Result<()> {
    let (isolate, store, keys) = fixture("authoritative original diary keyword".into())?;
    std::fs::write(
        isolate.path().join("diary-fragments-v1.db"),
        b"corrupt derived cache",
    )?;
    let result = search(&store, &keys, "keyword", 5, 4000, false)?;
    assert_eq!(result.items.len(), 1);
    assert!(!result.semantic_ready);
    Ok(())
}
